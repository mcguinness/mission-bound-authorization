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
    target: https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/10/
    author:
      -
        ins: D. Hardt
        name: Dick Hardt
    date: 2026
    seriesinfo:
      Internet-Draft: draft-hardt-oauth-aauth-protocol-10
  I-D.draft-mcguinness-aauth-mission-expiry:
    title: "AAuth Mission Expiry"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-aauth-mission-expiry.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

informative:
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
tree recorded for it.  An immutable expiry defined by the AAuth
Mission Expiry extension ends a mission automatically.  Termination
reasons are audit facts and never protocol states.  The operations extend the existing AAuth `mission_endpoint`,
use AAuth HTTP Message Signatures for agent calls, preserve the privacy
of the mission blob, and record their results in the mission log.

Termination immediately closes Person Server decision and issuance
paths, but it cannot by itself retract every credential already accepted
by every resource.  This document therefore specifies best-effort
revocation by AAuth token identity `(iss, jti)` and requires deployments
to report and bound the residual window honestly.

--- middle

# Introduction

The AAuth Protocol {{I-D.draft-hardt-oauth-aauth-protocol}} makes agent
governance orthogonal to its four resource-access modes.  An agent and
its Person Server (PS) hold the exact bytes of an approved mission blob.
The SHA-256 digest of those bytes, paired with the approving PS URL,
forms the native Mission Reference.  Resources and Access Servers see
that reference, not the mission body.  The PS retains the context and
ordered mission log needed to make governance decisions.

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

This specification reuses the existing `mission_endpoint`.  A mission
proposal in the base protocol has no `operation` member.  A management
request defined here has an `operation` member and a `mission` member,
so the two request forms are unambiguous.  A separate management
endpoint would create another discovery, authentication, and policy
surface without changing the trust boundary: the approving PS remains
the only server that can interpret the reference and change its state.

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

All requests in this specification identify exactly one target mission
using:

~~~ json
{
  "approver": "https://ps.example",
  "s256": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
}
~~~

The syntax, comparison, and digest rules are those of the AAuth Mission
Reference.  The `approver` value MUST exactly equal the `issuer` in the
metadata of the PS receiving the request.  A PS MUST NOT forward a
management operation to another approver and MUST NOT accept an alias
for either member.

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

Mission expiry is defined by AAuth Mission Expiry
{{I-D.draft-mcguinness-aauth-mission-expiry}}: an OPTIONAL `expires_at`
member of the approved mission blob, covered by `s256`, immutable in
place, and enforced by the PS on every decision path.  This profile
does not redefine that mechanism.

This profile adds the observable consequences.  The transition that
extension requires at or after `expires_at` is committed with
termination reason `expired` and attributed to the PS scheduler
({{logging}}).  The status operation exposes the approved expiry
({{status}}).  An explicit terminate that races automatic expiry
resolves as {{idempotency}} specifies: the first committed transition
wins, and the losing operation observes an idempotent outcome.

# Endpoint and Discovery {#endpoint}

## Extending the Mission Endpoint

All operations below use an HTTP `POST` {{RFC9110}} with a JSON body
{{RFC8259}} to the `mission_endpoint` in the PS metadata.  Management
requests have this common shape:

~~~ json
{
  "operation": "status",
  "mission": {
    "approver": "https://ps.example",
    "s256": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  }
}
~~~

The request MUST use `Content-Type: application/json`.  The PS MUST
reject duplicate JSON member names.  Unknown members MUST be ignored
unless they prevent safe processing.  Unknown operations fail with
`unsupported_operation`.

An Agent request MUST be signed using the AAuth HTTP Message Signatures
profile {{RFC9421}} and MUST present its Agent Token in `Signature-Key`.  The
covered components and content integrity requirements are those of the
base AAuth profile.  A management request is never authorized from the
Mission Reference alone.

This placement follows the base protocol's own definition of
`mission_endpoint` as the URL for mission lifecycle operations, of
which mission creation is one; the operations here are additional
lifecycle operations at that surface.  A native mission proposal
carries no `operation` member, so the discrimination is unambiguous.
The base protocol does not reserve the `operation` member: if a future
AAuth revision defines its own operation discrimination or
request-shape rules at `mission_endpoint`, that definition governs and
this profile will align with it.  A caller SHOULD confirm that an
operation appears in `mission_management_operations_supported`
({{metadata}}) before sending it, because the base protocol does not
define how a PS without this profile processes an operation-shaped
request.

## Metadata {#metadata}

A PS supporting this specification adds the following member to its
`/.well-known/aauth-person.json` metadata:

~~~ json
{
  "issuer": "https://ps.example",
  "mission_endpoint": "https://ps.example/mission",
  "mission_management_operations_supported": [
    "status", "terminate", "delegation_tree"
  ]
}
~~~

`mission_management_operations_supported` is an array of case-sensitive
operation strings.  The array MUST contain `status` and `terminate` for
conformance to this specification.  It contains `delegation_tree` when
the PS implements {{delegation-tree}}.  Unknown values MUST be ignored.

The base AAuth `mission_endpoint` member remains the only endpoint
advertised by this profile.  The base protocol also defines a
`mission_control_endpoint` metadata member; a PS MAY retain it for a
deployment-specific administrative user interface, but it MUST NOT use
that member to advertise the interoperable operations defined here.

# Authentication and Authorization {#authorization}

The PS MUST authenticate every caller before disclosing status or tree
data or changing state.  It MUST authorize the operation against the
target mission after authentication and before existence is disclosed.

## Owning Agent

The Owning Agent is authenticated exactly as at other AAuth PS
endpoints.  The `sub` of the verified Agent Token MUST exactly match the
`agent` member of the mission blob, and the request signature MUST
verify with the token-bound key.

The Owning Agent MAY:

* read status for its mission;
* request its delegation tree if the PS exposes that operation to
  agents; and
* terminate its mission with reason `revoked`.

An Agent does not directly assert `completed`.  It uses AAuth's
`completion` interaction, after which the Person's acceptance causes the
PS to terminate with reason `completed`.  A sub-agent MUST NOT call this
endpoint: AAuth requires its parent to mediate PS operations.

## Person

The PS authenticates the Person using its normal person-facing channel.
This specification does not replace the PS's account authentication or
session protocol.  The PS MUST bind that authenticated Person to the
person represented by the mission and MUST prevent tenant or account
selection from being supplied solely by the request body.

The Person MAY read status and delegation data, and MAY terminate with
reason `completed`, `revoked`, or `superseded`.  For `superseded`, the PS
SHOULD require the replacement Mission Reference and verify that the
same Person authorized both missions before recording the relationship.

## Administrator and Management Service

The PS MAY authorize an administrator or management service.  Such a
principal MUST be authenticated using a phishing-resistant,
sender-constrained mechanism appropriate to the deployment.  A remote
machine caller using AAuth HTTP Message Signatures MUST present a token
or key reference the PS recognizes as a management identity; an Agent
Token alone MUST NOT confer administrative privilege.

Administrative authorization MUST be least-privilege and scoped at
least by tenant or person population and operation.  Access to
delegation data SHOULD be a separate privilege from termination.
Administrative reason `administrative` MUST be limited to this role.

The PS MUST record the authenticated principal, effective role, policy
decision, and declared operational purpose for every successful
administrative request.  It SHOULD require step-up authentication or
dual control for high-blast-radius automation.  This profile does not
define fleet enumeration or bulk termination.

# Status Operation {#status}

A caller reads one mission by sending `operation` equal to `status`.

~~~ http
POST /mission HTTP/1.1
Host: ps.example
Content-Type: application/json
Signature-Input: sig=("@method" "@authority" "@path" \
    "content-type" "content-digest" "signature-key");created=1775581200
Signature: sig=:...signature bytes...:
Signature-Key: sig=jwt;jwt="eyJhbGc..."
Content-Digest: sha-256=:...:

{
  "operation": "status",
  "mission": {
    "approver": "https://ps.example",
    "s256": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  }
}
~~~

After authenticating and authorizing the caller, the PS returns:

~~~ json
{
  "mission": {
    "approver": "https://ps.example",
    "s256": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  },
  "state": "terminated",
  "approved_at": "2026-04-07T14:30:00Z",
  "expires_at": "2026-04-14T14:30:00Z",
  "terminated_at": "2026-04-10T09:12:43Z",
  "termination_reason": "revoked"
}
~~~

`mission`, `state`, and `approved_at` are REQUIRED.  `expires_at` is
present only if it is in the mission blob
({{I-D.draft-mcguinness-aauth-mission-expiry}}).  `terminated_at` is an
RFC 3339 `date-time` {{RFC3339}}; it and `termination_reason` are
REQUIRED when `state` is `terminated` and MUST be absent while it is
`active`.

The response is current at the instant the PS evaluates the request.
It is not a promise that the state will remain active.  An Agent MUST
stop initiating work when it receives `terminated`.  Polling is a
freshness mechanism, not the safety floor: every PS endpoint still
enforces mission state itself.

# Terminate Operation {#terminate}

## Request

Termination uses `operation` equal to `terminate`.  It requires a
`request_id` carrying at least 128 bits of unpredictable or
collision-resistant entropy encoded as a string.

~~~ json
{
  "operation": "terminate",
  "mission": {
    "approver": "https://ps.example",
    "s256": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  },
  "reason": "revoked",
  "request_id": "t-4f52f8d70a514703b54ca0c677f82d67",
  "purpose": "User withdrew authorization"
}
~~~

`reason` and `request_id` are REQUIRED.  `purpose` is OPTIONAL for an
Owning Agent or Person and REQUIRED for an administrator.  `purpose` is
an audit string, not executable policy, and MUST be rendered as
untrusted text.

For `superseded`, a Person or administrator MAY include:

~~~ json
"replacement": {
  "approver": "https://ps.example",
  "s256": "QmV0dGVyTWlzc2lvbkRpZ2VzdFZhbHVlMTIzNDU2Nzg5MDE"
}
~~~

The replacement is related evidence, not an alternate key for the
target operation.  It MUST identify an already approved mission that
the caller is authorized to reference.  Replacement validation is
subject to {{errors}}: a replacement that is absent, unapproved, or
outside the caller's authorization fails uniformly with
`invalid_request`, and the failure MUST NOT disclose which condition
held or anything else about the referenced mission.

## Atomic Transition

The PS performs these actions in order:

1. authenticate and authorize the caller;
2. apply expiry and read the current state under a transaction or
   equivalent serialization mechanism;
3. if active, atomically commit `terminated`, `terminated_at`, the
   reason, actor, and `request_id` to the mission log;
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
  "mission": {
    "approver": "https://ps.example",
    "s256": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  },
  "state": "terminated",
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
calls.  It records agent relationships in `parent_agent`, `act`, and the
Auth Tokens issued or provided under the same Mission Reference.  The
tree operation reports those native relationships; it MUST NOT invent a
second child mission identifier or imply algebraic scope inheritance.

An authorized caller sends:

~~~ json
{
  "operation": "delegation_tree",
  "mission": {
    "approver": "https://ps.example",
    "s256": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  },
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
  "mission": {
    "approver": "https://ps.example",
    "s256": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  },
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

`mission`, `as_of`, `nodes`, and `complete` are REQUIRED.  When another
page exists, `next_cursor` is REQUIRED and `complete` is false.  A node
contains an `agent` and one of `root`, `sub_agent`, or `call_chain` as
`relationship`.  A non-root node contains `parent_agent`.  `tokens` MAY
be returned to a Person or authorized administrator and SHOULD be
omitted from an Agent response unless required for that Agent's own
revocation accounting.

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

Errors use `application/problem+json` {{RFC9457}} as profiled by AAuth.  The
following error strings are defined:

| Error | HTTP status | Meaning |
| --- | --- | --- |
| `invalid_request` | 400 | The JSON or required members are invalid. |
| `invalid_mission_reference` | 400 | The reference syntax or local approver check failed. |
| `unsupported_operation` | 400 | The PS does not support the requested operation. |
| `invalid_termination_reason` | 400 | The reason is unknown or not permitted for the operation. |
| `idempotency_conflict` | 409 | The request identifier was reused with different content. |
| `mission_not_found` | 404 | The mission does not exist or the caller is not authorized to know it exists. |
| `rate_limited` | 429 | The caller exceeded a PS policy limit. |

For a syntactically valid reference, a PS MUST return the same status,
error, body shape, header set, and observably equivalent timing whether
the mission is absent or the authenticated caller lacks authorization.
The PS MUST use `mission_not_found` for both.  It MUST NOT disclose the
state, Agent identifier, timestamps, expiry, reason, or tenant before
authorization succeeds.

Malformed references can fail before lookup.  Repeated failures MUST be
rate limited and security logged.  Logs for probes MUST avoid storing
raw references longer than needed; a keyed digest can support abuse
correlation without building a reusable existence index.

The base `mission_terminated` error remains the response when an Agent
attempts another PS operation under a terminated mission.  The
authenticated `status` and `terminate` operations defined here instead
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
* a Resource that ignored `AAuth-Mission`;
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

Polling exposes access patterns to the PS and network observers.  Agents
SHOULD use a cadence proportionate to risk and SHOULD stop polling after
terminal status.  The management surface defines no push channel.

# Security Considerations {#security}

## Reference Substitution and Cross-PS Confusion

An attacker can substitute a known `s256` or send a reference for a
different PS.  Exact pair comparison, the local `approver` check,
signature verification, and authorization against the resolved mission
are all mandatory.  Neither member is interpreted as a fetch URL.  The
PS never retrieves a mission from a caller-selected location.

## Request Replay

A termination replay is safe only if its content is bound to the
signature and its idempotency rules are enforced.  The request body
MUST have content integrity under the AAuth HTTP Message Signatures
profile.  The PS enforces signature freshness and nonce/replay policy as
defined by AAuth and binds `request_id` to authenticated caller and exact
content.  Logging a repeated request must not overwrite the first
reason or create a false second transition.

## Compromised Agents

A compromised Owning Agent can terminate its own mission, causing
denial of service.  It cannot gain authority by doing so and cannot
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
page completeness and observational completeness.  Token `act` claims
and `parent_agent` values are accepted only after their normal AAuth
verification; unverified caller assertions never create edges.

## Transport

All operations use HTTPS and the TLS requirements of
{{I-D.draft-hardt-oauth-aauth-protocol}} and {{RFC9325}}.  Responses
SHOULD carry cache controls preventing shared caching.  Management
clients MUST validate the PS metadata issuer and endpoint origin before
sending references or credentials.

# IANA Considerations {#iana}

This document requests no IANA registrations.

This specification does define new wire elements:

* the `mission_management_operations_supported` Person Server metadata
  member;
* the `status`, `terminate`, and `delegation_tree` operation values;
* the JSON request and response members defined by {{endpoint}},
  {{status}}, {{terminate}}, and {{delegation-tree}}, including the
  token-residual and pagination members;
* the termination-reason values in {{state}} and the `root`,
  `sub_agent`, and `call_chain` relationship values; and
* the error values in {{errors}}.

The AAuth Protocol does not currently establish an IANA registry for
Person Server metadata members, mission-endpoint operations or JSON
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

1. implements `status` and `terminate` at the existing
   `mission_endpoint` and advertises both operations;
2. keys every operation solely by the exact `{approver, s256}` Mission
   Reference and requires `approver` to equal its metadata issuer;
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
{{I-D.draft-mcguinness-aauth-mission-expiry}} and to {{expiry}} in
full.  Delegation-tree support is OPTIONAL.  If
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
