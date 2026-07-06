---
title: "Mission Management for OAuth 2.0"
abbrev: "OAuth Mission Management"
category: std

docname: draft-mcguinness-oauth-mission-management-latest
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
 - management
 - enumeration
 - incident response
 - revocation
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-management.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC3339:
  RFC7515:
  RFC7519:
  RFC8259:
  RFC8414:
  RFC9325:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-latest
  I-D.draft-mcguinness-oauth-mission-status:
    title: "Mission Status and Lifecycle for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-status.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-status-latest

informative:
  RFC9110:
  RFC9700:
  I-D.draft-mcguinness-oauth-mission-expansion:
    title: "Mission Expansion for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-expansion.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-expansion-latest
  I-D.draft-mcguinness-oauth-mission-child-delegation:
    title: "Mission Child Delegation for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-child-delegation.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-child-delegation-latest
  I-D.draft-mcguinness-oauth-mission-signals:
    title: "Mission Lifecycle Signals for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-signals.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-signals-latest
  I-D.draft-mcguinness-mission-authority-server:
    title: "Mission Authority Server"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-authority-server.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-mission-authority-server-latest
  I-D.draft-mcguinness-mission-audit:
    title: "Mission Audit Transparency"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-audit.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-mission-audit-latest
  I-D.draft-mcguinness-mission-security-model:
    title: "Mission Security Model"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-security-model.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-mission-security-model-latest

--- abstract

The Mission Status and Lifecycle profile observes and changes one
Mission at a time and defers fleet-scale management. This document
defines that deferred surface: a Mission Management endpoint through
which an authorized Management Client enumerates the Missions a
Mission Issuer holds, filtered by Subject, client, state, creation
time, expiry, or parent, and applies bulk lifecycle operations to the
enumerated set through a dry-run-then-execute exchange whose bulk
token pins the evaluated membership. The surface is management-plane
and operator-facing: authorized for the existence knowledge the status
profile's anti-oracle rules deny to ordinary consumers, audited on
every call, and never exposed to the agents whose Missions it manages.
It is optional; a deployment that does not adopt it is unaffected.

--- middle

# Introduction

The Mission Status and Lifecycle profile
{{I-D.draft-mcguinness-oauth-mission-status}} (the "status profile")
answers "what is the state of this Mission" and changes that state,
one Mission per request. Its Deferred Lifecycle Capabilities section
defers two fleet-scale capabilities: Mission enumeration ("which
Missions exist for this Subject, client, or state") and bulk lifecycle
operations over the enumerated set. This document specifies both.

The two surfaces are deliberate counterparts. The status profile is
consumption-plane: its callers are authorized for individual Missions,
so it makes an unknown reference indistinguishable from an
unauthorized one. This document is management-plane: its callers are
operator consoles and incident-response tooling in the Mission
Issuer's own trust domain, explicitly authorized for existence
knowledge over a declared filter scope, compensated not by
indistinguishability but by explicit authorization and mandatory audit
of every call ({{filter-scope}}). The surface is never agent-facing:
the Agent executing a Mission has no role here
({{management-authentication}}).

Both capabilities share one endpoint, one request shape, one
authentication and authorization model, one signing discipline, and
one audit rule; a request's `operation` member selects between them.
Bulk operations apply the status profile's per-Mission lifecycle
semantics unchanged, so this document adds no state, no transition,
and no event type to the lifecycle state space. It is OPTIONAL and
does not restate the issuance profile
{{I-D.draft-mcguinness-oauth-mission}} or the status profile; a
deployment that does not adopt it is unaffected.

# Conventions and Terminology {#conventions-and-definitions}

{::boilerplate bcp14-tagged}

This document uses the terms defined in the issuance profile
{{I-D.draft-mcguinness-oauth-mission}} and the status profile
{{I-D.draft-mcguinness-oauth-mission-status}}, in particular Mission,
Mission Issuer (the Mission `origin`: in this document's OAuth binding
the Authorization Server; a standalone Mission Issuer, the Mission
Authority Server {{I-D.draft-mcguinness-mission-authority-server}},
serves this surface with the same semantics), `mission_id`, the
Mission record, and the Mission lifecycle states and operations. It
additionally uses:

Management Client:
: An authenticated client authorized for the Mission Management
  endpoint: an operator console, incident-response tooling, or
  administrative automation acting in the Mission Issuer's trust
  domain. An Agent executing a Mission is never a Management Client.

All JSON shown in this document is non-normative and illustrative; the
member definitions in the surrounding text are authoritative. HTTP
message examples follow the conventions of {{RFC9110}}; long values
are wrapped for display. JWT examples are shown as decoded JSON; on
the wire the JWS Compact Serialization {{RFC7515}} applies.

# Mission Management Endpoint {#management-endpoint}

The Mission Issuer publishes its Mission Management endpoint URL in
Authorization Server metadata ({{as-metadata}}) as
`mission_management_endpoint`. The endpoint MUST be served over TLS
1.2 or later (TLS 1.3 RECOMMENDED), following the recommendations of
{{RFC9325}}.

A request is an HTTPS POST whose body is a JSON object {{RFC8259}}
sent as `application/json`; the structured filter does not fit the
form encoding of the status profile's single-Mission operations. Every
request carries:

`operation`:
: REQUIRED. A string. `enumerate` ({{enumeration}}) or one of the
  status profile's lifecycle operations `revoke`, `suspend`,
  `resume`, `complete`, applied in bulk ({{bulk-lifecycle}}).

`filter`:
: REQUIRED. An object ({{filter}}) selecting the Missions the
  operation addresses.

`nonce`:
: REQUIRED. A string. A client-generated nonce, unique per request
  within the response lifetime, echoed in the signed response. It is
  also the idempotency key: the AS MUST deduplicate management
  requests by (client, `nonce`) for a bounded window and, on a
  retransmit, MUST replay the original response rather than
  re-execute the request.

A success response is a JWS Compact Serialization {{RFC7515}} signed
with a key published in the Mission Issuer's `jwks_uri`, following the
status profile's signing discipline: the JWS header carries a `kid`
and a `typ` of `mission-management-response+jwt`, the algorithm is one
advertised in `mission_status_signing_alg_values_supported`
({{as-metadata}}), and the status profile's signing-key retention
rules apply. The HTTP `Content-Type` is `application/jwt` {{RFC7519}}
with `Cache-Control: no-store`; the `typ` value is a local-use
identifier defined by this document ({{iana}}). The signed payload
carries the envelope `iss`, `aud` (the authenticated caller), `sub`
(the acting party), `nonce`, `iat`, and `exp`, plus the members of
{{enumeration-response}}, {{dry-run}}, or {{manifest}}. Before
honoring a response a Management Client MUST apply the status
profile's response verification checks (signature, `iss`, `aud`,
`sub`, `nonce`, `iat`/`exp` with up to 30 seconds skew) and MUST
verify the `typ`.

Rate limits, the enumeration page maximum, and the bulk size bound are
deployment-declared operational configuration; this document defines
the error symbols that surface them ({{management-errors}}) but no
metadata for them.

## Authentication {#management-authentication}

The request MUST be authenticated using the status profile's mechanism
set ({{I-D.draft-mcguinness-oauth-mission-status}}, Section
"Authentication"): mTLS client authentication, a DPoP-bound bearer
token, or private-key-JWT client authentication, discovered through
the AS's existing client-authentication metadata {{RFC8414}}. Plain
Basic or POST client authentication MUST NOT be used. A deployment
MUST NOT accept at the Management endpoint an authentication mechanism
weaker than those it accepts at its Mission Lifecycle endpoint. When a
sender-constrained access token authenticates the call, it MUST carry
a management authorization: a `mission_management` scope or an
equivalent deployment-defined grant, distinct from the status
profile's lifecycle grant.

The surface is management-plane only. A Mission Issuer MUST NOT
authorize an Agent (the OAuth client that submitted or executes a
Mission) as a Management Client, and MUST NOT accept a Mission-bound
access token as authentication here.

## Authorization and Filter Scope {#filter-scope}

A deployment authorizes each Management Client for a **filter scope**:
the Missions it may enumerate and operate on, expressed over the
filter members of {{filter}}. A subject-scoped operator, a
client-scoped operator, and a tenant-wide incident responder are
distinct grants; the grant syntax is deployment-defined. The AS MUST
evaluate a request's filter against the caller's filter scope before
evaluating it against the Mission store, and MUST refuse with
`forbidden` ({{management-errors}}) a request whose filter could match
a Mission outside that scope.

This surface intentionally inverts the status profile's anti-oracle
property. That property exists because status callers are not
authorized for existence knowledge; a Management Client is, over
exactly its filter scope, so unknown and unauthorized references need
not be indistinguishable here and `forbidden` is returned openly. The
compensating control is audit: the AS MUST record every management
request, including refused ones, in its audit log with the caller, the
`operation`, the full `filter`, the `purpose` or `reason`, the result
count or outcome manifest, and the disposition. A refusal is computed
from the caller's grant and the request alone, never from Mission
data, so it discloses nothing about which Missions exist.

# Mission Filter {#filter}

The `filter` object selects Missions by conjunction: a Mission matches
when it satisfies every member present. An empty filter matches every
Mission in the caller's filter scope. The members, each OPTIONAL,
match against the Mission record
({{I-D.draft-mcguinness-oauth-mission}}, Section "Mission Record"):

`subject`:
: An object with `iss` and `sub`. Matches the record's `subject`
  exactly.

`client_id`:
: A string. Matches the record's `client_id`.

`state`:
: An array of strings. Matches a Mission whose current lifecycle
  state equals any listed value, drawn from the issuance profile's
  open state space as extended by the profiles the deployment runs.
  The AS MUST NOT refuse a filter for carrying a state value it does
  not produce; such a value matches no Mission.

`created_after`, `created_before`:
: RFC 3339 {{RFC3339}} date-times. Match a Mission whose `created_at`
  is strictly after, respectively strictly before, the value.

`expiring_before`:
: An RFC 3339 {{RFC3339}} date-time. Matches a Mission whose
  `expires_at` is strictly before the value.

`parent`:
: A string, a Mission Identifier. Matches the Child Missions whose `parent`
  lineage member names it
  ({{I-D.draft-mcguinness-oauth-mission-child-delegation}}): direct
  children only. A caller walks a delegation tree level by level.

The AS MUST refuse a filter carrying an unrecognized member with
`invalid_request`, so a filter is never silently broader than the
caller intended.

# Mission Enumeration {#enumeration}

The `enumerate` operation answers "which Missions exist" for the
caller's filter, returning signed pages of Mission summaries. In
addition to the common members ({{management-endpoint}}), the request
carries:

`purpose`:
: REQUIRED. A string, maximum 1024 characters. The operator's reason
  for the query (for example a ticket or case identifier), recorded
  in audit ({{filter-scope}}).

`cursor`:
: OPTIONAL. A string. An opaque pagination cursor from a prior
  response.

`limit`:
: OPTIONAL. A positive integer. The AS returns at most the smaller of
  `limit` and its deployment-declared page maximum, and applies the
  maximum when `limit` is absent.

## Response {#enumeration-response}

The signed payload ({{management-endpoint}}) carries:

`missions`:
: REQUIRED. An array of Mission summary objects, each carrying
  `id`, `state`, `subject` (an object with `iss` and `sub`),
  `client_id`, `created_at`, and `expires_at` from the Mission
  record, plus the lineage members `successor`, `predecessor`
  ({{I-D.draft-mcguinness-oauth-mission-expansion}}), and `parent`
  ({{I-D.draft-mcguinness-oauth-mission-child-delegation}}) where
  present on the record. A summary MUST NOT carry the Mission Intent,
  the Authority Set, or any member beyond these: enumeration answers
  which Missions exist and stand in what state; a caller needing full
  detail resolves each Mission through Mission Status, which is
  separately authorized.

`cursor`:
: CONDITIONAL. A string. Present exactly when more results remain;
  the caller re-sends the same request with this cursor to continue.

A cursor is opaque and bound to the (caller, `filter`) that produced
it; the AS MUST refuse with `invalid_request` a cursor presented by a
different caller or with a different filter. Result order MUST be
stable within a cursor walk. The AS SHOULD present a consistent
membership across a walk but MAY reflect transitions committed while
it is in progress; a caller that needs a pinned membership uses the
bulk dry run ({{dry-run}}), whose bulk token provides exactly that.

## Worked Example {#enumeration-example}

An incident responder (`client_secops-console`) triages a credential
compromise for Subject `user_3p2q8mN1a0kV7tR` and enumerates that
Subject's active Missions:

~~~ http-message
POST /as/mission/manage HTTP/1.1
Host: as.example.com
Content-Type: application/json
Authorization: DPoP eyJhbGciOiJFUzI1NiIsImtpZCI6...
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2Iiwi...

{
  "operation": "enumerate",
  "filter": {
    "subject": { "iss": "https://idp.example.com",
                 "sub": "user_3p2q8mN1a0kV7tR" },
    "state": ["active"]
  },
  "purpose": "IR-4192: credential compromise triage",
  "limit": 50,
  "nonce": "nonce_M4kR8vT2nQ7xB5sW"
}
~~~

Decoded signed response payload:

~~~ json
{
  "iss": "https://as.example.com",
  "aud": "client_secops-console",
  "sub": "client_secops-console",
  "nonce": "nonce_M4kR8vT2nQ7xB5sW",
  "iat": 1797845340,
  "exp": 1797845400,
  "missions": [
    { "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
      "state": "active",
      "subject": { "iss": "https://idp.example.com",
                   "sub": "user_3p2q8mN1a0kV7tR" },
      "client_id": "s6BhdRkqt3",
      "created_at": "2026-10-15T14:32:11Z",
      "expires_at": "2026-12-31T23:59:59Z" }
  ]
}
~~~

No `cursor` is present: the result is complete. The AS records the
caller, filter, purpose, and result count in its audit log.

# Bulk Mission Lifecycle {#bulk-lifecycle}

A bulk request applies one lifecycle operation of the status profile
(`revoke`, `suspend`, `resume`, `complete`) to every Mission a filter
matches, in two steps: a REQUIRED dry run returning the match count
and a bulk token pinning the evaluated membership, then an execute
presenting that token. In addition to the common members
({{management-endpoint}}), the request carries:

`mode`:
: REQUIRED. A string, `dry_run` or `execute`.

`bulk_token`:
: CONDITIONAL. A string. REQUIRED when `mode` is `execute`; MUST NOT
  be sent otherwise.

`reason`:
: REQUIRED. A string, maximum 1024 characters. Recorded in audit
  ({{filter-scope}}) and applied as each per-Mission transition's
  `reason` under the status profile, so it surfaces in per-Mission
  audit and, where signals run, in each emitted event
  ({{I-D.draft-mcguinness-oauth-mission-signals}}).

`suspend_until`, `on_expiry`:
: OPTIONAL and CONDITIONAL respectively, valid only when `operation`
  is `suspend`, with the status profile's semantics, applied
  uniformly to every Mission in the set.

The AS MAY declare a bound on the evaluated set size and refuse a dry
run whose match count exceeds it with `filter_too_broad`
({{management-errors}}); the caller narrows the filter (for example
with `created_after`) and retries.

## Dry Run {#dry-run}

On `mode` `dry_run` the AS evaluates the filter within the caller's
filter scope ({{filter-scope}}), records the matched membership, and
returns a signed response carrying:

`operation`:
: REQUIRED. The requested operation, echoed.

`match_count`:
: REQUIRED. An integer. The size of the evaluated membership.

`bulk_token`:
: REQUIRED. A string. An opaque, single-use token binding the caller,
  the `operation`, the `filter` (with `suspend_until` and `on_expiry`
  when present), and the evaluated membership itself: the exact set
  of `mission_id` values matched at dry-run time
  ({{bulk-token-security}}).

`bulk_token_expires_at`:
: REQUIRED. An RFC 3339 {{RFC3339}} date-time. The bulk token's
  expiry. Its lifetime is deployment-defined and SHOULD NOT exceed 15
  minutes: long enough to review, short enough that the reviewed set
  cannot silently age.

A dry run commits no transition. To review the membership behind the
count, the caller runs `enumerate` with the same filter.

## Execution {#execution}

On `mode` `execute` the AS MUST verify that the presented `bulk_token`
is unexpired and unused, was issued to this caller, and binds an
`operation` and `filter` equal to the request's; on any mismatch it
MUST refuse with `invalid_bulk_token` and execute nothing. The token
is then consumed: it is single-use whatever the outcome.

The AS applies the operation to each member of the bound membership
individually, under the status profile's lifecycle semantics
unchanged: legality per its Legal Transitions, idempotency,
per-transition evidence and audit, and, where signals run, one
`mission.lifecycle-change` SET per committed transition
({{I-D.draft-mcguinness-oauth-mission-signals}}). There is no bulk
event type and no transactionality: transitions commit independently,
and a failure on one member MUST NOT roll back another.

The membership is the one the dry run evaluated. A Mission created, or
newly matching the filter, after the dry run is not in the membership
and MUST NOT be operated on; a member that transitioned in the interim
yields an `already_terminal` or `illegal_transition` outcome rather
than a surprise transition ({{bulk-token-security}}).

## Outcome Manifest {#manifest}

The execute response is a signed manifest carrying `operation` (the
executed operation, echoed) and:

`results`:
: REQUIRED. An array of objects, one per member of the executed
  membership, each carrying `mission_id`, `outcome`, and, on `error`
  only, an OPTIONAL `detail` string.

The outcomes:

| Outcome | Meaning |
|---|---|
| `applied` | The operation succeeded: the transition was committed, or the Mission already stood in the operation's resulting non-terminal state (the status profile's idempotent case). |
| `already_terminal` | The Mission was already in a terminal state, including the operation's own resulting state; nothing remained to stop. |
| `illegal_transition` | The operation is not legal from the Mission's current non-terminal state; the Mission is unchanged. |
| `error` | The AS failed to process this Mission; its state is unverified. |

A Mission in any terminal state reports `already_terminal`, taking
precedence over the idempotent reading of `applied`; it is reported
distinctly from `error` because, for a terminating operation, an
already-terminal member is a satisfied objective, not a failure. After
a partial failure the spent bulk token is not reusable; the caller
remediates with a fresh dry run over the same filter and a new
execute: members already transitioned then report `already_terminal`,
and only `error` members are retried.

## Worked Example {#bulk-example}

Continuing {{enumeration-example}}, the responder revokes every
Mission for the compromised Subject in any state, so the filter omits
`state`. Dry-run request body (transport and authentication as in
{{enumeration-example}}):

~~~ json
{
  "operation": "revoke",
  "filter": {
    "subject": { "iss": "https://idp.example.com",
                 "sub": "user_3p2q8mN1a0kV7tR" }
  },
  "mode": "dry_run",
  "reason": "IR-4192: subject credential compromise",
  "nonce": "nonce_P9sB3xV7mK1tR6qZ"
}
~~~

Decoded dry-run response payload:

~~~ json
{
  "iss": "https://as.example.com",
  "aud": "client_secops-console",
  "sub": "client_secops-console",
  "nonce": "nonce_P9sB3xV7mK1tR6qZ",
  "iat": 1797845400,
  "exp": 1797845460,
  "operation": "revoke",
  "match_count": 3,
  "bulk_token": "blk_7Nq4xW2rT9mK5vB8sD1zA6pY3cE0hJfL",
  "bulk_token_expires_at": "2026-11-02T09:45:00Z"
}
~~~

The count is 3, more than the enumeration above: without `state` the
filter also matches a suspended and a completed Mission (`revoke` is
legal from `suspended`, so suspended Missions belong in the sweep).
The responder executes,
re-sending the same `operation` and `filter` with `mode` of `execute`,
the `bulk_token`, the same `reason`, and a fresh `nonce`
(`nonce_W2tN6bQ9kX4mV8rS`). Decoded manifest payload, with a partial
failure:

~~~ json
{
  "iss": "https://as.example.com",
  "aud": "client_secops-console",
  "sub": "client_secops-console",
  "nonce": "nonce_W2tN6bQ9kX4mV8rS",
  "iat": 1797845580,
  "exp": 1797845640,
  "operation": "revoke",
  "results": [
    { "mission_id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
      "outcome": "applied" },
    { "mission_id": "msn_6VbT1yHn4RwQk9x3zE8sC5j2MpDfL0G-",
      "outcome": "already_terminal" },
    { "mission_id": "msn_0JpW3xEr8KtNb5v2qC7mD4h1YsAgF9L-",
      "outcome": "error",
      "detail": "state store timeout" }
  ]
}
~~~

One Mission was revoked, emitting its own lifecycle signal where
signals run; the completed Mission needed nothing; one failed. The
responder re-runs the dry run over the same filter, reviews the new
count, and executes again: the revoked and completed members report
`already_terminal` and only the failed one is retried.

# Error Responses {#management-errors}

A wire error returns the matching HTTP status with a JSON object
{{RFC8259}} body carrying `error`, `error_description`, and `nonce`,
as in the status profile. Per-Mission conditions during a bulk execute
are manifest outcomes ({{manifest}}), never wire errors. The codes:

| `error` | HTTP | Description |
|---|---|---|
| `invalid_request` | 400 | Malformed request: unknown `operation`, unrecognized filter member, invalid member combination, or a cursor that does not match its caller and filter. |
| `invalid_bulk_token` | 400 | The bulk token is missing, expired, already used, issued to another caller, or bound to a different operation or filter. |
| `filter_too_broad` | 400 | The filter matches more Missions than the deployment's declared bound for the requested operation. |
| `unauthorized` | 401 | Request not authenticated. |
| `forbidden` | 403 | Caller authenticated but not authorized for the requested operation or filter scope ({{filter-scope}}). |
| `rate_limited` | 429 | Caller is rate-limited. |
| `unavailable` | 503 | The AS temporarily cannot serve management requests. |

For `rate_limited`, the response SHOULD include a `Retry-After` header
{{RFC9110}} and a `retry_after` body member in seconds.

# Incident Response Patterns {#incident-patterns}

This section is non-normative. Common incident shapes compose the two
operations directly:

- **Compromised Subject.** Filter `subject`, enumerate to triage, then
  bulk `revoke` (the worked examples above).
- **Decommissioned client.** Filter `client_id`, bulk `revoke`; every
  Mission the retired Agent submitted stops deriving.
- **Key or approval-surface compromise.** Filter `created_after` and
  `created_before` around the compromise window, bulk `revoke`; every
  Mission approved while the surface was suspect is terminated,
  regardless of Subject or client.
- **Suspend-first triage.** Bulk `suspend` with `suspend_until` and
  `on_expiry` of `revoke`, investigate, then selectively `resume`
  individual Missions through the status profile's lifecycle endpoint;
  anything not affirmatively cleared revokes itself at the deadline.

What bulk revocation does and does not stop is the security model's
revocation-to-action latency table
({{I-D.draft-mcguinness-mission-security-model}}): each revocation
stops new derivation at commit, while tokens already derived persist
until the tightest propagation layer the deployment runs cuts them
off. Bulk management changes how many Missions one request can stop,
not how fast any one revocation propagates.

# Deferred Management Capabilities {#deferred-management}

Approver transfer, re-anchoring a Mission's consent to a different
accountable party, is not defined here. Administrative monotonic
narrowing, such as shortening a Mission's `expires_at` or retiring
a single Authority Set entry, is not defined here. Cross-origin
enumeration, one query spanning Missions held by multiple Mission
Issuers, is not defined here; a Management Client queries each
`origin` it is authorized for separately.

# Authorization Server Metadata {#as-metadata}

An AS that serves the Mission Management endpoint advertises it in its
Authorization Server metadata {{RFC8414}}:

`mission_management_endpoint`:
: OPTIONAL. A string containing a URL. The URL of the Mission
  Management endpoint ({{management-endpoint}}). Present when the AS
  serves it.

Because management responses reuse the status profile's signing
discipline, an AS that publishes `mission_management_endpoint` MUST
also publish `mission_status_signing_alg_values_supported`
({{I-D.draft-mcguinness-oauth-mission-status}}).

A standalone Mission Issuer (a Mission Authority Server
{{I-D.draft-mcguinness-mission-authority-server}}) MAY serve this
surface and, when it does, carries the same member with the same
semantics in its discovery document; {{iana}} registers the member in
the Mission Authority Server Metadata registry.

# Security Considerations {#security-considerations}

The security considerations of the issuance profile
{{I-D.draft-mcguinness-oauth-mission}} and the status profile
{{I-D.draft-mcguinness-oauth-mission-status}} apply. This section
covers what is specific to fleet-scale management.

## Blast Radius {#blast-radius}

This endpoint is the highest-blast-radius surface in this suite: one
authorized request can terminate or suspend every Mission in a filter
scope, and one enumeration can disclose a tenant's entire Mission
population. Accordingly, the authentication floor of
{{management-authentication}} is at least the lifecycle endpoint's
with a distinct management grant, every call including every refusal
is audited ({{filter-scope}}), and destructive operations are
structurally two-step, since an execute cannot exist without the dry
run that pinned its membership.

A compromised Management Client is equivalent to an operator
compromise of the Mission Issuer's management plane: within its filter
scope it can enumerate at will and stop or suspend all governed work.
It is a trusted-base component in the sense of the security model
({{I-D.draft-mcguinness-mission-security-model}}); its compromise is
not prevented here, only bounded by the filter scope and recorded by
the mandatory audit trail. Its abuse ceiling is disclosure and work
stoppage, not authority escalation: the surface cannot create or widen
a Mission, and the model's availability trade applies, since a
management credential converts into stopped governed work rather than
loosened enforcement. Deployments SHOULD scope Management Clients
narrowly, protect their credentials as operator credentials, and alert
on anomalous management activity; where audit transparency runs,
management audit records are candidates for it
({{I-D.draft-mcguinness-mission-audit}}). The `purpose` and `reason`
strings that flow into those records, and into per-Mission evidence
and signals, are caller-written free text; audit systems MUST treat
them as untrusted input.

## Enumeration-Oracle Inversion {#oracle-inversion}

The status profile makes Mission existence unobservable to the
unauthorized; this document makes it queryable by the authorized. The
two compose safely only if the boundary between them holds: a
deployment MUST NOT satisfy a management request with a credential
authorized only for status or lifecycle calls, and the filter-scope
check of {{filter-scope}} MUST run before any Mission data is touched,
so a refusal is data-independent. The audit rule is the compensating
control for the disclosure this surface exists to provide.

## Bulk Token Binding {#bulk-token-security}

The bulk token closes the review-to-execution gap, and each of its
bindings ({{dry-run}}) is load-bearing. The membership binding
prevents time-of-review to time-of-execution growth: without it, a
filter re-evaluated at execute time could match Missions created after
the operator reviewed the dry-run count, so a reviewed "revoke these
3" could silently become "revoke these 30". Single use prevents a
captured or logged token from re-running the sweep; the short lifetime
bounds how stale the reviewed set can be; and the caller binding keeps
the reviewed set and the executing principal the same. An AS MUST
enforce all four; a bulk token that survives reuse, transfer, or
filter substitution reduces the two-step exchange to a one-step sweep.

## General OAuth Security

This document inherits OAuth 2.0 Best Current Practice {{RFC9700}} for
the OAuth surfaces it composes with; implementers MUST follow current
OAuth security guidance.

# Privacy Considerations {#privacy-considerations}

The privacy considerations of the issuance and status profiles apply.
This section covers what is specific to enumeration.

An enumeration response is PII-bearing by construction: each summary
row ties a Subject identifier to an Agent, a lifecycle state, and
activity timing, and a page of rows profiles a person's delegated
activity. Minimization is structural: the summary shape of
{{enumeration-response}} excludes the Mission Intent and the Authority
Set, and the filter-scope authorization of {{filter-scope}} bounds
each Management Client to the population it demonstrably needs. A
deployment SHOULD grant tenant-wide filter scopes only to
incident-response roles.

The audit records of {{filter-scope}} are doubly sensitive: they carry
the Subject identifiers of the Missions touched, and they record which
operator investigated which person, when, and why. Deployments MUST
treat them as PII sinks under the issuance profile's privacy rules,
retain them for at least the audit horizon of the Missions they
concern ({{I-D.draft-mcguinness-oauth-mission}}), and restrict read
access to them at least as tightly as the management surface itself.

# Conformance {#conformance}

This document is OPTIONAL. An implementation that claims it conforms
in one of two roles.

A **Management-capable Mission Issuer** serves the Mission Management
endpoint over the authentication and authorization of
{{management-authentication}} and {{filter-scope}} with signed
responses per {{management-endpoint}}; serves `enumerate`
({{enumeration}}) and the bulk lifecycle operations
({{bulk-lifecycle}}) with dry-run-then-execute and the bulk token
bindings of {{dry-run}}; applies bulk transitions per Mission under
the status profile's lifecycle semantics, emitting per-Mission
evidence and signals ({{execution}}); audit-logs every management
request per {{filter-scope}}; and advertises
`mission_management_endpoint` ({{as-metadata}}).

A **Management Client** authenticates per
{{management-authentication}}; sends the REQUIRED `purpose` or
`reason` on every request, identifying the operator task rather than a
fixed placeholder; obtains a fresh dry run for every execute,
surfacing the `match_count` to the deciding operator or decision point
before executing; and executes only bulk tokens from dry runs it
itself requested.

An implementation that supports neither role is unaffected and remains
a conforming issuance or status profile implementation.

# IANA Considerations {#iana}

## Metadata Registrations

IANA is requested to register `mission_management_endpoint` in the
"OAuth Authorization Server Metadata" registry {{RFC8414}}, and in the
"Mission Authority Server Metadata" registry established by
{{I-D.draft-mcguinness-mission-authority-server}}, whose registration
policy is Specification Required; this document is the specification.
For both: Change Controller IETF; Reference this document,
{{as-metadata}}.

## Media Type

This document registers no media type. A management response is served
as `application/jwt` {{RFC7519}} and identified by its JWS header
`typ` of `mission-management-response+jwt` ({{management-endpoint}}),
a local-use type identifier following this suite's convention for
issuer-signed artifacts that need a distinguishing `typ` without a
dedicated media type.

# Acknowledgments
{:numbered="false"}

The author thanks the implementers and reviewers of the Mission-Bound
Authorization work for the incident-response experience that shaped
this surface.

--- back
