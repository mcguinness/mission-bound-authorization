---
title: "AAuth Mission Management"
abbrev: "AAuth Mission Management"
category: std

docname: draft-mcguinness-mission-aauth-management-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - aauth
 - mission
 - agent
 - management
 - lifecycle
 - revocation
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-aauth-management.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC3339:
  RFC8259:
  RFC9110:
  RFC9325:
  RFC9421:
  RFC9457:
  I-D.draft-hardt-oauth-aauth-protocol:
    title: "AAuth Protocol"
    target: https://dickhardt.github.io/AAuth/draft-hardt-oauth-aauth-protocol.html
    author:
      -
        ins: D. Hardt
        name: Dick Hardt
    date: 2026

informative:
  I-D.draft-mcguinness-aauth-mission-expiry:
    title: "AAuth Mission Expiry"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-aauth-mission-expiry.html
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
  I-D.draft-mcguinness-mission-security-model:
    title: "Mission Security Model"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-security-model.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

--- abstract

AAuth defines an immutable mission blob, identifies it by the native
`{approver, s256}` mission reference, and gives a mission two states:
`active` and `terminated`.  It leaves revocation, delegation-tree
queries, and administrative interfaces to a companion specification.
This document defines that companion.

An authenticated caller can read status, permanently terminate an
authorized mission, and inspect the AAuth agent and token delegation
tree recorded for it.  An immutable expiry, AAuth's `expires_at`,
ends a mission automatically.  Termination
reasons are audit facts and never protocol states.  The operations are
actions on AAuth's `mission_control_endpoint`, authenticate their
callers with mechanisms the base protocol and the Person Server
already have, preserve the privacy of the mission blob, and record
their results in the mission log.

Termination immediately closes Person Server decision and issuance
paths, but it cannot by itself retract every credential already accepted
by every resource.  This document therefore specifies best-effort
revocation by AAuth token identity `(iss, jti)` and requires deployments
to report and bound the residual window honestly.

--- middle

# Introduction

The AAuth Protocol {{I-D.draft-hardt-oauth-aauth-protocol}} makes agent
governance orthogonal to its five resource-access modes.  An agent and
its Person Server (PS) hold the exact bytes of an approved mission blob.
The SHA-256 digest of those bytes, paired with the approving PS URL,
forms the native Mission Reference.

Resources and Access Servers see that reference, not the mission
body.  The PS retains the context and ordered mission log needed to
make governance decisions.

AAuth also deliberately gives a mission only two states.  An `active`
mission can be used; a `terminated` mission has ended permanently.
There is no pause or resume operation.  The base protocol defines
completion through the interaction endpoint and defers other
transitions, administrative access, and delegation-tree queries.

This document supplies those management functions without replacing
AAuth's mission model with an OAuth authorization object.  In
particular, it introduces no `mission_id`, Authority Set, scope-subset
rule, status signal, or additional lifecycle state.  Every operation is
keyed by the exact native `{approver, s256}` pair.  Authorization to a
remote resource remains a decision of that resource, its Access Server,
and, where involved, the PS; this endpoint manages the contextual
governance envelope held by the PS.

The family architecture situates this surface among the lifecycle
companions ({{I-D.draft-mcguinness-mission-architecture}}), and the
family security model's analysis applies to it
({{I-D.draft-mcguinness-mission-security-model}}).

The base protocol splits the surfaces: `mission_endpoint` is the
owning agent's, and parties other than the owning agent read and
manage missions at the `mission_control_endpoint`, whose
authentication model, operations, and responses AAuth charters to a
companion specification with exactly this document's scope.  This
document defines them there.

Each operation is an `action` on a mission's own control-plane URL,
adopting the per-mission URL convention and the `action` discriminator
the base protocol defines at `mission_endpoint`.  The approving PS
remains the only server that can interpret the reference and change
its state.

# Conventions and Terminology {#conventions}

{::boilerplate bcp14-tagged}

This document uses Person, Agent, Agent Provider (AP), Person Server
(PS), Access Server (AS), Resource, Agent Token, Resource Token, Auth
Token, Mission, Mission Reference, mission blob, and mission log as
defined by {{I-D.draft-hardt-oauth-aauth-protocol}}.

The following additional terms are used:

Management Principal:
: An authenticated person, administrator, or service acting under an
  administrative policy of the PS.  An Agent is not a Management
  Principal merely because it possesses its Agent Token.

Owning Agent:
: The Agent whose identifier is the `agent` member of the approved
  mission blob.

Termination Reason:
: An audit fact explaining why an `active` mission became `terminated`.
  It does not add a state or permit reactivation.

Tracked Auth Token:
: An Auth Token that the PS issued or provided under a Mission Reference
  and for which it retained at least `iss`, `jti`, `aud`, and `exp`.

Residual Window:
: The interval after termination during which already-issued authority
  might still be accepted because revocation has not reached a Resource
  or because an independently issued or opaque credential is outside
  the PS's control.

# Native Mission Management Model {#model}

## Mission Identity

The Mission Reference `{approver, s256}` remains the management key
for every mission this specification governs.  On the wire, a request
identifies its target with the `{mission_s256}` path segment of the
mission's own control-plane URL,
`{mission_control_endpoint}/{mission_s256}`, following the per-mission
URL convention the base protocol defines at `mission_endpoint`.

The syntax, comparison, and digest rules are those of the AAuth Mission
Reference.  `approver` is neither a request member nor a path segment:
it is fixed to the identity of the PS endpoint that receives the
request, so no part of the request can name another approver.  A PS
MUST resolve the `{mission_s256}` segment only among the missions it
itself approved, MUST NOT forward a management operation to another
approver, and MUST NOT accept an alias for either half of the
reference.

The pair is the sole protocol key.  Implementations MAY use internal
database keys, but those keys MUST NOT appear in this protocol.  The PS
MUST NOT require the caller to send the mission blob, and a status or
tree response MUST NOT return it.

The Mission Reference is integrity-protected but is not a secret.
Possession of it conveys no management authority.

## State and Termination Reasons {#state}

The only protocol states are:

* `active`: the mission is in progress; and
* `terminated`: the mission has permanently ended.

Only `active` permits the PS to process a token, permission, audit, or
interaction request under the mission.  Once the PS commits
`terminated`, it MUST NOT return the mission to `active`.  A caller that
needs to continue the work creates and obtains approval for a new
mission.

This specification defines these termination reasons:

| Reason | Meaning |
| --- | --- |
| `completed` | The Person accepted completion of the work. |
| `revoked` | The Person, Owning Agent, or an authorized administrator withdrew the mission. |
| `expired` | The mission reached its approved `expires_at` time. |
| `superseded` | The Person or an authorized administrator replaced the mission with another approved mission. |
| `administrative` | An authorized administrator ended the mission under local policy. |

A Termination Reason is stored beside lifecycle data, outside the
immutable mission blob.  It MUST NOT be exposed as `mission_status`,
mapped to a new state, or used to permit a later transition.  A PS MAY
support extension reasons.  A recipient that does not recognize a
reason MUST retain the `terminated` state and treat the reason as an
opaque audit value.

## Optional Expiry {#expiry}

Mission expiry is defined by AAuth
{{I-D.draft-hardt-oauth-aauth-protocol}}: an OPTIONAL `expires_at`
member of the approved mission blob, covered by `s256`, immutable in
place, and enforced by the PS on every decision path.  This profile
does not redefine that mechanism.  AAuth Mission Expiry
{{I-D.draft-mcguinness-aauth-mission-expiry}} remains an informative
profile of the same native member for deployments that cite it.

This profile adds the observable consequences.  The transition AAuth
requires at or after `expires_at` is committed with termination reason
`expired` and attributed to the PS scheduler ({{logging}}), surfaced
through AAuth's `mission_terminated` error and `mission_status` rather
than a separate status value.  The status operation exposes the
approved expiry ({{status}}).  An explicit terminate that races
automatic expiry resolves as {{idempotency}} specifies: the first
committed transition wins, and the losing operation observes an
idempotent outcome.

# Endpoint and Discovery {#endpoint}

## The Mission Control Plane

Every operation below is an action on one mission's control-plane URL.
A caller makes an HTTP `POST` {{RFC9110}} with a JSON body
{{RFC8259}} to `{mission_control_endpoint}/{mission_s256}`, where
`mission_control_endpoint` is the PS metadata member ({{metadata}})
and `{mission_s256}` is the target mission's digest:

~~~ json
{
  "action": "status"
}
~~~

`action` is REQUIRED, and its value is `status` ({{status}}),
`terminate` ({{terminate}}), or `delegation_tree`
({{delegation-tree}}).  A PS MUST reject a request with a missing or
unrecognized `action` with `invalid_request`, the same response the
base protocol requires of a missing or unrecognized `action` at
`mission_endpoint`.  A caller SHOULD confirm that an action appears
in `mission_control_actions_supported` ({{metadata}}) before sending
it.

The mission's identity comes from the path and from nowhere else.  A
request body MUST NOT carry a `mission_s256` member, and a PS MUST
reject a body that does with `invalid_request`.  Response bodies
continue to report `mission_s256`, and the `replacement_s256` member
of a `superseded` termination ({{terminate}}) names a different
mission as related evidence.

The request MUST use `Content-Type: application/json`.  The PS MUST
reject duplicate JSON member names.  Unknown members MUST be ignored
unless they prevent safe processing.

Every request MUST be authenticated as {{authorization}} requires for
the caller's class.  A request signed with the AAuth HTTP Message
Signatures profile {{RFC9421}} uses the covered components and content
integrity requirements of the base AAuth profile.  A management
operation is never authorized from the Mission Reference alone.

This document defines no action at the bare
`{mission_control_endpoint}` URL.  A PS MAY serve a deployment's
human-facing administrative interface there, as the base protocol
permits.

## What Stays at the Mission Endpoint

`mission_endpoint` remains the owning agent's surface, carrying only
the base protocol's three operations: proposing a mission at the bare
URL, and the `update` and `completion` actions at a mission's own URL.
This document defines no member and no `action` value at
`mission_endpoint`.

## Metadata {#metadata}

A PS supporting this specification publishes the base protocol's
`mission_control_endpoint` and adds the following member to its
`/.well-known/aauth-person.json` metadata:

~~~ json
{
  "issuer": "https://ps.example",
  "mission_control_endpoint": "https://ps.example/mission-control",
  "mission_control_actions_supported": [
    "status", "terminate", "delegation_tree"
  ]
}
~~~

`mission_control_actions_supported` is an array of case-sensitive
action strings.  The array MUST contain `status` and `terminate` for
conformance to this specification.  It contains `delegation_tree` when
the PS implements {{delegation-tree}}.  Unknown values MUST be ignored.

`mission_control_endpoint` is OPTIONAL in the base protocol.  A PS
that does not publish it implements no operation of this
specification, whatever `mission_control_actions_supported` would
advertise.  A caller MUST resolve the endpoint from the metadata and
MUST NOT construct it from `mission_endpoint`.

# Authentication and Authorization {#authorization}

The PS MUST authenticate every caller before disclosing status or tree
data or changing state.  It MUST authorize the action against the
target mission after authentication and before existence is disclosed.

This document defines no new token type and no new credential.  Each
caller class authenticates with a mechanism the base protocol or the
PS already has.

## Person

The PS authenticates the Person using its normal person-facing channel.
This specification does not replace the PS's account authentication or
session protocol.  The PS MUST bind that authenticated Person to the
person represented by the mission and MUST prevent tenant or account
selection from being supplied solely by the request body.

The Person MAY read status and delegation data, and MAY terminate with
reason `completed`, `revoked`, or `superseded`.  For `superseded`,
`replacement_s256` is REQUIRED, and the PS SHOULD verify that the
same Person authorized both missions before recording the relationship.

## Administrator

The PS MAY authorize a human administrator, authenticated through the
PS's own administrative channel with a phishing-resistant,
sender-constrained mechanism appropriate to the deployment, bound to
the tenant or person population the administrator governs.  An Agent
Token alone MUST NOT confer administrative privilege.

Administrative authorization MUST be least-privilege and scoped at
least by tenant or person population and action.  Access to
delegation data SHOULD be a separate privilege from termination.
Administrative reason `administrative` MUST be limited to this role.

The PS MUST record the authenticated principal, effective role, policy
decision, and declared operational purpose for every successful
administrative request.  It SHOULD require step-up authentication or
dual control for high-blast-radius automation.  This profile does not
define fleet enumeration or bulk termination.

## Management Service

A management service authenticates with the AAuth HTTP Message
Signatures profile {{RFC9421}}, presenting its key with
`Signature-Key: sig=jwks_uri`, the scheme the base protocol uses for
PS-to-AS token requests.  The PS resolves the key as the
`Signature-Key` profile specifies and MUST hold a deployment-local
registration of that `jwks_uri` as a management identity; this
specification adds no discovery surface for management identities.  An
Agent MUST NOT use this scheme; the base protocol already forbids it
to agents.

A management service is subject to the administrative rules above:
least-privilege scoping, a separate privilege for delegation data,
`administrative` limited to the administrator role, and the recorded
principal, role, decision, and purpose on every successful request.

## Owning Agent

Whether the control plane admits the Owning Agent is a PS decision.
The base protocol describes the control plane as the surface for
parties other than the owning agent, and gives the owning agent no
base operation that terminates a mission.

Where a PS admits the Owning Agent at the control plane, that agent
MAY read status for its own mission and MAY terminate its own mission
with reason `revoked`, and the PS MAY expose the delegation tree for
that mission to it.  The agent authenticates exactly as at other AAuth
PS endpoints: it presents its Agent Token with `Signature-Key:
sig=jwt`, the signature MUST verify with the token-bound key, and the
`sub` of the verified Agent Token MUST exactly match the `agent`
member of the mission blob.

Where a PS does not admit the Owning Agent, that agent is an
authenticated caller without authorization for the mission, and
{{errors}} applies to it unchanged: it receives `mission_not_found`.
Its path to ending the work is the base protocol's completion, and
this document defines no `action` at `mission_endpoint`.

An Agent does not directly assert `completed`.  It uses AAuth's
`completion` operation, after which the Person's acceptance causes the
PS to terminate with reason `completed`.  A sub-agent MUST NOT call
this endpoint: AAuth requires its parent to mediate PS operations.

## Ambient Credentials

Every action defined here is a JSON `POST` authenticated as this
section requires.  A PS that serves a human-facing interface at the
same origin MUST NOT let an ambient credential, such as a cookie or
session a browser attaches automatically, satisfy that
authentication.

# Status Operation {#status}

A caller reads one mission by sending `action` equal to `status` to
the mission's control-plane URL.

~~~ http
POST /mission-control/dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk \
    HTTP/1.1
Host: ps.example
Content-Type: application/json
Signature-Input: sig=("@method" "@authority" "@path" \
    "content-type" "content-digest" "signature-key");created=1775581200
Signature: sig=:...signature bytes...:
Signature-Key: sig=jwks_uri; \
    jwks_uri="https://mgmt.example/.well-known/jwks.json"
Content-Digest: sha-256=:...:

{
  "action": "status"
}
~~~

After authenticating and authorizing the caller, the PS returns:

~~~ json
{
  "mission_s256": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
  "mission_status": "terminated",
  "approved_at": "2026-04-07T14:30:00Z",
  "expires_at": "2026-04-14T14:30:00Z",
  "terminated_at": "2026-04-10T09:12:43Z",
  "termination_reason": "revoked",
  "observed_at": "2026-04-10T09:15:02Z",
  "fresh_until": "2026-04-10T09:15:32Z"
}
~~~

`observed_at` and `fresh_until` are REQUIRED RFC 3339 `date-time`
values {{RFC3339}}: the instant the PS evaluated the mission's state,
and the latest instant a consumer may rely on this response.  The
interval between them is deployment policy and MAY follow a published
maximum staleness.

`mission_s256`, `mission_status`, and `approved_at` are REQUIRED.  The
`mission_status` member reuses the name and values the base protocol
carries in its `mission_terminated` error body.  `expires_at` is
present only if it is in the mission blob
({{I-D.draft-hardt-oauth-aauth-protocol}}).  `terminated_at` is an
RFC 3339 `date-time` {{RFC3339}}; it and `termination_reason` are
REQUIRED when `mission_status` is `terminated` and MUST be absent
while it is `active`.

The response reports state as of `observed_at` and is reliable until
`fresh_until`; it is not a promise that the state will remain active.
A consumer MUST NOT rely on a response after its `fresh_until`, and a
failed, invalid, unrecognized, or stale response establishes nothing:
the consumer MUST fail closed and MUST NOT treat the mission as
`active` on its basis.  An Agent that reads status here MUST stop
initiating work when it receives `terminated`.  Polling is a
freshness mechanism, not the safety floor: every PS endpoint still
enforces mission state itself.

<!-- family-status: BEGIN (generated from family-manifest.json; exact-matched by scripts/check-family-manifest.mjs) -->
Role: companion. Spec maturity: experimental. Maintenance: frozen-until-upstream-release.
Implementation: not yet in the conformance ledger (conformance-manifest.json).
Adopt when: Alongside the AAuth binding: status, termination, delegation-tree queries.
Requires: nothing beyond its listed references.
<!-- family-status: END -->

# Terminate Operation {#terminate}

## Request

Termination uses `action` equal to `terminate`.  It requires a
`request_id` carrying at least 128 bits of unpredictable or
collision-resistant entropy encoded as a string.

~~~ json
{
  "action": "terminate",
  "reason": "revoked",
  "request_id": "t-4f52f8d70a514703b54ca0c677f82d67",
  "purpose": "User withdrew authorization"
}
~~~

`reason` and `request_id` are REQUIRED.  `purpose` is OPTIONAL for a
Person or an admitted Owning Agent and REQUIRED for an administrator
or a management service.  `purpose` is an audit string, not
executable policy, and MUST be rendered as untrusted text.

For `superseded`, the request MUST include the replacement:

~~~ json
"replacement_s256": "QmV0dGVyTWlzc2lvbkRpZ2VzdFZhbHVlMTIzNDU2Nzg5MDE"
~~~

The replacement is related evidence, not an alternate key for the
target operation.  It MUST identify an already approved mission that
the caller is authorized to reference; it is validated before, and
committed in, the atomic transition.  A `superseded` request without
`replacement_s256` fails with `invalid_request` as a missing member.
Replacement validation is subject to {{errors}}: a replacement that
is unresolvable, unapproved, or outside the caller's authorization
fails uniformly with `invalid_request`, and the failure MUST NOT
disclose which condition held or anything else about the referenced
mission.

## Atomic Transition

The PS performs these actions in order:

1. authenticate and authorize the caller;
2. apply expiry and read the current state under a transaction or
   equivalent serialization mechanism;
3. if active, atomically commit `terminated`, `terminated_at`, the
   reason, actor, `request_id`, and, for `superseded`, the validated
   `replacement_s256` to the mission log;
4. make that state visible to every local PS decision and issuance path;
5. initiate revocation of outstanding Auth Tokens as described in
   {{token-consequences}}, without waiting for all attempts to finish;
   and
6. return the committed result and the revocation summary current at
   response time.

Step 3 is the authority-closing commit.  External revocation MUST NOT be
allowed to delay or roll it back.  The PS MAY wait for a short, bounded
set of immediate revocation results before responding, and revocation
attempts MAY continue asynchronously.

The PS returns `200 OK` with the status representation and a revocation
summary:

~~~ json
{
  "mission_s256": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
  "mission_status": "terminated",
  "terminated_at": "2026-04-10T09:12:43Z",
  "termination_reason": "revoked",
  "token_residual": {
    "tracked": 4,
    "revocation_attempted": 4,
    "revocation_confirmed": 3,
    "residual_until": "2026-04-10T10:02:00Z",
    "complete": false
  }
}
~~~

The counters disclose only tokens the caller is authorized to know
about.  `complete` is true only when every Tracked Auth Token is either
confirmed revoked or expired and the PS knows of no untracked access
mode for the mission.  `residual_until` is the latest `exp` among
unconfirmed Tracked Auth Tokens.  It MUST be omitted when no residual is
known and MUST NOT be presented as a complete bound if untracked or
opaque credentials may exist.

## Idempotency and Concurrency {#idempotency}

The PS MUST retain the result associated with `(authenticated caller,
request_id)` for at least 24 hours and SHOULD retain it for the mission
log's lifetime.  Repeating an identical request returns the original
result without a second lifecycle event.  Reusing a `request_id` with
different request content fails with `idempotency_conflict`.

Termination is also semantically idempotent across request identifiers.
If the mission is already terminated, an authorized caller receives its
existing terminal status.  The first committed reason and timestamp
remain authoritative; a later request MUST NOT overwrite them.  A PS
MAY append an audit entry noting the later authorized request.

Concurrent requests are serialized.  At most one request records the
active-to-terminated transition.  Completion, expiry, and administrative
termination obey the same rule.

# Delegation-Tree Operation {#delegation-tree}

AAuth does not create child Mission objects for sub-agents or chained
calls.  It records agent relationships in `parent_agent` and in the
Auth Tokens issued or provided under the same Mission Reference; auth
and resource tokens carry no chain claim, so the PS itself holds the
call-chain state.  The tree operation reports those native
relationships; it MUST NOT invent a second child mission identifier or
imply algebraic scope inheritance.

An authorized caller sends:

~~~ json
{
  "action": "delegation_tree",
  "max_results": 100,
  "cursor": "opaque-next-page-value"
}
~~~

`max_results` and `cursor` are OPTIONAL.  A cursor MUST be opaque to the
caller, integrity protected, scoped to the caller and Mission
Reference, and short lived.  The PS MUST set and document a maximum
page size.

The response contains the relationships the PS observed while
processing the mission:

~~~ json
{
  "mission_s256": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
  "as_of": "2026-04-10T09:15:00Z",
  "nodes": [
    {
      "agent": "aauth:planner.7f3c@vendor.example",
      "relationship": "root"
    },
    {
      "agent": "aauth:planner.7f3c+search1@vendor.example",
      "relationship": "sub_agent",
      "parent_agent": "aauth:planner.7f3c@vendor.example",
      "tokens": [
        { "iss": "https://as.search.example", "jti": "token-19" }
      ]
    }
  ],
  "complete": true
}
~~~

`mission_s256`, `as_of`, `nodes`, and `complete` are REQUIRED.  When another
page exists, `next_cursor` is REQUIRED and `complete` is false.

A node contains an `agent` and one of `root`, `sub_agent`, or
`call_chain` as `relationship`.  A non-root node contains
`parent_agent`.  `tokens` MAY
be returned to a Person or authorized administrator and SHOULD be
omitted from a response to an admitted Owning Agent unless required
for that Agent's own revocation accounting.

The result is observational, not exhaustive proof.  Identity-based
calls and resource-managed access can occur without a PS token request.
An intermediary can make a downstream call outside the PS's view.
`complete` means only that the returned page exhausts the PS's current
records; it MUST NOT be described as proof that no other delegation or
resource access occurred.

The PS MUST authorize every returned node for the caller.  It MUST NOT
leak another tenant's agent identifiers, token identifiers, topology,
or activity.  Tree reads are sensitive events and MUST be recorded in
the mission log or, for rejected/unknown references, a security audit
log that does not create a false mission record.

# Error Responses and Anti-Oracle Behavior {#errors}

Errors use `application/problem+json` {{RFC9457}} as profiled by AAuth.
`invalid_request` and `mission_not_found` carry the same strings and
statuses as the base protocol's mission-endpoint errors, so one
vocabulary spans the agent's surface and the control plane; the
remaining errors below are defined by this document.

| Error | HTTP status | Meaning |
| --- | --- | --- |
| `invalid_request` | 400 | The `{mission_s256}` path segment is malformed, `action` is missing or unrecognized, the body carries `mission_s256`, or a required member is invalid. |
| `invalid_termination_reason` | 400 | The reason is unknown or not permitted for the caller. |
| `mission_not_found` | 404 | The mission does not exist or the caller is not authorized to know it exists. |
| `idempotency_conflict` | 409 | The request identifier was reused with different content. |
| `rate_limited` | 429 | The caller exceeded a PS policy limit. |

For a syntactically valid `{mission_s256}` segment, a PS MUST return
the same status, error, body shape, header set, and observably
equivalent timing whether the mission is absent or the authenticated
caller lacks authorization for it, and MUST answer both identically
within each caller class.  The PS MUST use `mission_not_found` for
both.  It MUST NOT disclose the state, Agent identifier, timestamps,
expiry, reason, or tenant before authorization succeeds.

The base protocol makes a terminated mission deliberately
distinguishable to the agent that owns it, at that agent's own
`mission_endpoint`, because that agent already knows the mission
exists.  That carve-out does not extend to a caller unauthorized for
the mission here: `mission_not_found` covers absent and unauthorized
alike, and terminal status is returned only to an authorized caller.

A malformed path segment MAY fail before lookup.  Repeated failures
MUST be rate limited and security logged.  Logs for probes MUST avoid
storing raw references longer than needed; a keyed digest can support
abuse correlation without building a reusable existence index.

The base `mission_terminated` error remains the response when an Agent
attempts another PS operation under a terminated mission.  The
authenticated `status` and `terminate` actions defined here instead
return terminal status so an authorized caller can learn the result.

# Mission Log and Retention {#logging}

The PS MUST append an ordered mission-log event for:

* every authorized status read;
* every committed termination, including automatic expiry and accepted
  completion;
* every authorized termination request received after termination;
* every token-revocation attempt and result; and
* every authorized delegation-tree read.

A management event MUST contain the Mission Reference, PS-local ordered
sequence value, event time, event type, authenticated actor and role,
authorization decision or policy reference, and, when applicable,
`request_id`, termination reason, purpose, and token-impact summary.
Token events identify a token by the pair `(iss, jti)`, never `jti`
alone.  The PS MUST NOT place private keys, raw Agent Tokens, raw Auth
Tokens, or the mission blob in a management event merely to satisfy this
requirement.

Automatic expiry is attributed to the PS scheduler, not to the Agent or
Person.  Completion remains attributed to the Person who accepted the
Agent's completion interaction.  A security log MUST capture rejected
administrative requests and oracle probes without associating an
unverified reference with a real mission.

The PS MUST retain the terminal state and its reason for at least as
long as any Tracked Auth Token could remain valid, plus the deployment's
audit and dispute period.  It SHOULD retain the immutable mission blob
and log for the same period when lawful.  Retention limits, deletion,
legal holds, and access controls MUST be documented.  Deletion of the
mission body MUST NOT cause the PS to treat a formerly terminated
reference as active; the PS retains a tombstone sufficient to reject it
for the maximum relevant replay and audit horizon.

# Consequences for Tokens and Requests {#token-consequences}

## Local Gating

Immediately after the terminal commit, the PS MUST reject every new
token, permission, audit, and interaction request under the Mission
Reference with the AAuth `mission_terminated` error.  It MUST stop
federating resource-token requests under that mission.  This is the
reliable AAuth management effect because it occurs at the server that
owns the mission context.

A Resource Token is a signed request artifact, not authority.  It does
not need revocation; submitting it under the terminated mission fails at
the PS.  Terminating a mission does not revoke the Agent Token, because
the Agent identity can legitimately be used for another mission or for
missionless AAuth interactions.

## Tracking Auth Tokens

For each Auth Token it issues or provides under a mission, a conforming
PS MUST retain:

* the Mission Reference;
* the token's `iss` and `jti` as a compound identity;
* `aud` and `exp`;
* the Resource revocation endpoint, when advertised; and
* whether the PS issued the token or obtained it through federation.

The PS MUST NOT key revocation by `jti` alone.  It SHOULD also retain the
AS and Resource endpoints required to retry revocation.  These records
are sensitive and follow {{logging}}.

## Revocation Attempts

After termination, the PS SHOULD invoke each applicable AAuth
`revocation_endpoint` with `(iss, jti)` for every unexpired Tracked Auth
Token.  In PS-asserted access, this normally means the Resource.  In
federated access, the PS SHOULD notify the Resource and MAY also notify
the issuing AS as supported by the base AAuth protocol.  Retries MUST be
bounded, authenticated, rate limited, and recorded.

A `200` response or natural token expiry closes the tracked residual for
that token.  A timeout, unreachable endpoint, absent endpoint, or
ambiguous result remains unconfirmed until expiry.  The PS MUST NOT
report successful mission-wide revocation merely because it marked its
local state or contacted an AS.

## Honest Residual Bounds {#residuals}

Termination is not retroactive.  It cannot undo an action already
performed or necessarily stop an action already accepted.  A
self-contained Auth Token can remain acceptable until its `exp` unless
the Resource receives and enforces revocation.  Network partitions and
Resource policy therefore create an unavoidable residual window.

The PS can provide a time bound only for the Tracked Auth Tokens whose
expiry it knows.  The conservative tracked bound is the latest `exp`
among tokens not confirmed revoked.  If the PS cannot determine an
expiry, it MUST report the tracked residual as unbounded rather than
inventing a deadline.

The PS has no general visibility or control over:

* identity-based access where a Resource authorizes the Agent directly;
* an opaque `AAuth-Access` token issued in resource-managed access;
* a Resource that violated the base protocol's `mission_s256` copy rule;
* credentials or side effects acquired outside AAuth; or
* a downstream call made without returning through this PS.

Where any such path was possible, the PS MUST mark mission-wide
revocation completeness as false or unknown.  Deployment documentation
MUST state which AAuth access modes are covered, the maximum configured
Auth Token lifetime, whether Resources implement revocation, retry
policy, and the worst-case residual expected under partition.  Risky
deployments SHOULD use short Auth Token lifetimes and action-time
Resource checks in addition to PS gating.

The base AAuth text sometimes describes this action as revoking a
mission.  In this profile, "revoke the mission" means the single,
permanent transition to `terminated` with Termination Reason `revoked`.
It is not a distinct `revoked` state and does not invoke an OAuth token
revocation or status protocol for the mission itself.

# Privacy Considerations {#privacy}

A Mission Reference is correlatable anywhere it appears.  Status and
tree endpoints can amplify that correlation by revealing timestamps,
relationships, and token issuers.  The PS therefore discloses no mission
body, description, tools, justification, or log contents through this
profile and minimizes status fields to lifecycle facts.

Delegation trees expose organizational topology and Agent behavior.
They require distinct authorization, pagination bounds, and tenant
isolation.  Token identifiers SHOULD be omitted unless the caller needs
them for incident response.  User interfaces SHOULD summarize topology
without exposing raw identifiers by default.

Administrative purpose strings, termination reasons, and actor
identities can themselves be sensitive.  Access controls, encryption at
rest, retention limits, deletion policy, and audit access MUST be
documented.  A PS SHOULD support data-subject access and deletion where
applicable without deleting the minimum tombstone needed to keep a
terminated mission terminated.

Polling exposes access patterns to the PS and network observers.  A
caller SHOULD use a cadence proportionate to risk and SHOULD stop
polling after terminal status.  The management surface defines no push
channel.

# Security Considerations {#security}

## Reference Substitution and Cross-PS Confusion

An attacker can substitute a known `mission_s256` value in the request
path, including one issued by a different PS.  Exact digest comparison,
resolving `mission_s256` only within this PS's own approved-mission
store, signature verification, and authorization against the resolved
mission are all mandatory.  Because the target is a path segment, the
`@path` covered component of the base signature profile binds it to the
signature, so a captured signature cannot be redirected at another
mission.  `mission_s256` is not interpreted as a fetch URL.
The PS never retrieves a mission from a caller-selected location.

## Request Replay

A termination replay is safe only if its content is bound to the
signature and its idempotency rules are enforced.  The request body
MUST have content integrity under the AAuth HTTP Message Signatures
profile.  The PS enforces signature freshness and nonce/replay policy as
defined by AAuth and binds `request_id` to authenticated caller and exact
content.  Logging a repeated request must not overwrite the first
reason or create a false second transition.

## Compromised Agents

Where a PS admits the Owning Agent at the control plane, a compromised
Owning Agent can terminate its own mission, causing denial of service.
It cannot gain authority by doing so and cannot
reactivate the mission, choose administrative reasons, or manage another
mission.  The Person can create a newly approved mission after recovery.
Because an Agent request for completion still requires Person
acceptance, compromise cannot falsely record `completed` through this
endpoint.

## Administrative Blast Radius

Administrative credentials can terminate many missions even though
this profile exposes only single-mission operations.  A PS MUST scope
them, rate limit them, protect them with sender constraint, and audit
their use.  Management automation SHOULD require a declared purpose and
SHOULD use approval or dual control appropriate to its potential blast
radius.  The endpoint MUST NOT infer administrative authority from an
Agent's domain or `parent_agent` relationship.

## Races and Failures

The local terminal commit precedes external revocation.  Transactional
state evaluation prevents a token request racing with termination from
being issued after the commit.  Implementations MUST ensure every local
decision path consults the same authoritative state or a cache whose
failure behavior is fail closed.  Expiry is checked synchronously so a
failed scheduler cannot keep a mission active.

External failures do not restore the mission.  Revocation retries are
durable work and survive PS restarts.  A Resource that needs a stronger
cutoff cannot rely only on cached status or token expiry; it needs an
action-time decision or effective revocation mechanism.

## Log Integrity

The mission log influences future governance and is security-critical.
The PS MUST prevent Agents and ordinary operators from rewriting or
reordering it.  Sequence allocation, durable storage, authenticated
actor attribution, backup, and restricted access are required.  This
document does not require a public transparency mechanism, but a PS MAY
add tamper-evident storage or signed checkpoints.

## Delegation-Tree Limits

The returned tree is based on PS observations, not global execution.
Treating it as complete evidence can hide identity-based, opaque-token,
or off-path activity.  Consumers MUST preserve the distinction between
page completeness and observational completeness.  `parent_agent`
values and the PS's own issuance-linked chain state are accepted only
after their normal AAuth verification; unverified caller assertions
never create edges.

## Transport

All operations use HTTPS and the TLS requirements of
{{I-D.draft-hardt-oauth-aauth-protocol}} and {{RFC9325}}.  Responses
SHOULD carry cache controls preventing shared caching.  Management
clients MUST validate the PS metadata issuer and endpoint origin before
sending references or credentials.

# IANA Considerations {#iana}

This document requests no IANA registrations.

This specification does define new wire elements:

* the `mission_control_actions_supported` Person Server metadata
  member;
* the `status`, `terminate`, and `delegation_tree` `action` values;
* the JSON request and response members defined by {{endpoint}},
  {{status}}, {{terminate}}, and {{delegation-tree}}, including the
  token-residual and pagination members;
* the termination-reason values in {{state}} and the `root`,
  `sub_agent`, and `call_chain` relationship values; and
* the error values in {{errors}}.

The AAuth Protocol does not currently establish an IANA registry for
Person Server metadata members, mission control plane actions or JSON
members, termination reasons, delegation relationships, or AAuth error
values.  Consequently, there is no
applicable registry in which to register any of the wire elements above.
They are defined by this document and compared as specified here.

If AAuth creates applicable registries before publication, this document
will request registration of every corresponding element above rather
than relying on this no-action section.  Termination reasons remain
audit facts rather than lifecycle states; creating a reason registry
would not turn them into protocol states.  Extension specifications
defining new reasons need to specify their authorization, audit, and
privacy semantics.

# Conformance {#conformance}

An **AAuth Mission Management PS** conforms to this specification when
it:

1. publishes `mission_control_endpoint`, implements the `status` and
   `terminate` actions there, and advertises both in
   `mission_control_actions_supported`;
2. keys every action solely by the `{mission_s256}` path segment of
   the mission's control-plane URL, resolving it only among missions
   for which it is itself the `approver`;
3. preserves exactly the `active` and `terminated` states, makes
   termination permanent, and records reasons separately;
4. authenticates and authorizes every request according to caller role,
   with anti-oracle equivalence for absent and unauthorized references;
5. serializes expiry, completion, and termination, closes every local PS
   decision path at the terminal commit, and enforces idempotency;
6. records the management and revocation events required by
   {{logging}};
7. tracks Auth Tokens by `(iss, jti)`, attempts applicable revocation,
   and reports residual limits without claiming control over unseen or
   independently managed access; and
8. meets the security, privacy, retention, and TLS requirements of this
   document and the base AAuth Protocol.

Expiry support is OPTIONAL.  If implemented, the PS conforms to
AAuth's native `expires_at` definition and enforcement, to the
retained deltas of {{I-D.draft-mcguinness-aauth-mission-expiry}}, and
to {{expiry}} in full.  Delegation-tree support is OPTIONAL.  If
advertised, the PS conforms to {{delegation-tree}} in full.

A deployment claiming conformance MUST publish or otherwise make
available its caller-role authorization policy, Auth Token retention
period, supported access-mode coverage, maximum token lifetime,
revocation retry policy, expiry clock policy if used, and worst-case
residual behavior.  It MUST NOT claim that Mission termination revokes
identity-based, opaque resource-managed, or otherwise untracked access.

--- back

# Acknowledgments

The AAuth mission-management seam and two-state lifecycle were defined
by Dick Hardt in the AAuth Protocol.  This companion preserves those
native choices.
