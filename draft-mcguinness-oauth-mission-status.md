---
title: "Mission Status and Lifecycle for OAuth 2.0"
abbrev: "Mission Status"
category: std

docname: draft-mcguinness-oauth-mission-status-latest
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
 - status
 - lifecycle
 - revocation
venue:
  github: "mcguinness/draft-mcguinness-oauth-mission"
  latest: "https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-oauth-mission-status.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC6838:
  RFC7009:
  RFC7515:
  RFC7523:
  RFC7662:
  RFC8259:
  RFC8414:
  RFC8705:
  RFC9325:
  RFC9449:
  RFC9701:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-latest

informative:
  RFC9110:
  RFC9700:
  I-D.draft-mcguinness-oauth-mission-signals:
    title: "Mission Lifecycle Signals for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-signals-latest

--- abstract

The Mission-Bound Authorization for OAuth 2.0 profile
{{I-D.draft-mcguinness-oauth-mission}} (the "issuance profile") binds
issued authority to a durable, human-approved Mission and gates
issuance on Mission state, but it observes Mission state only through
token lifetime and optional token introspection. This document
defines the Mission state-management surfaces it defers: a canonical
Mission Status operation (keyed by `mission_id`), a management
endpoint for explicit lifecycle transitions (`revoke`, `suspend`, `resume`,
`complete`), revocation-propagation guidance, and signed
status evidence. Each capability is independently optional; an
implementation MAY adopt any subset, and one that adopts none remains
a conforming issuance profile. This document does not restate the base
profile.

--- middle

# Introduction

The issuance profile {{I-D.draft-mcguinness-oauth-mission}} makes a
Mission a first-class OAuth artifact: a structured, human-approved,
integrity-bound task whose authority bounds and outlives every token
an agent derives. It is, by design, a minimum-viable issuance layer.
It gates derivation on Mission state, carries the `mission` claim on
every derived token, and offers only OPTIONAL token introspection
({{I-D.draft-mcguinness-oauth-mission}}, Section "Mission State via
Token Introspection") as a way for a Resource Server to observe
Mission state. It explicitly leaves the canonical Mission Status
surface (keyed by `mission_id`), a standardized management endpoint
for lifecycle transitions, signed status evidence, and
revocation-propagation guidance to future work.

This document specifies those deferred surfaces as OPTIONAL extensions
that build on the issuance profile. The capabilities are:

- A dedicated **Mission Status operation**
  ({{mission-status}}), which any consumer holding a `mission_id`
  resolves, with responses signed as a JWS {{RFC7515}}.
- An extension to OAuth token introspection that carries a Mission
  projection, which a deployment MAY return as a {{RFC9701}}-signed
  response ({{introspection-projection}}).
- A **Mission Lifecycle endpoint** ({{mission-lifecycle-endpoint}})
  for explicit `revoke`, `suspend`, `resume`, and `complete`
  transitions, distinct from {{RFC7009}} token revocation.
- **Revocation propagation** guidance
  ({{revocation-enforcement-classes}}): a `mission_max_stale_seconds`
  bound and how to size token lifetimes to the propagation mechanisms
  in use.
- **Authorization Server metadata** members
  ({{as-metadata}}) advertising the endpoints above.

Each capability is independently optional. An implementation states
which it supports through the metadata of {{as-metadata}} and the
conformance language of {{conformance}}. An implementation that
supports none of them is unaffected and remains a conforming issuance
profile.

This document does not restate the base profile. The Mission Intent,
authority derivation, the `mission_resource_access` authorization
details type, the `mission` claim, the integrity anchors, Mission-bound
token issuance, the subset rule, and lifecycle gating are all defined
in {{I-D.draft-mcguinness-oauth-mission}} and are referenced, not
re-specified, here.

# Conventions and Terminology {#conventions-and-definitions}

{::boilerplate bcp14-tagged}

This document uses the terms defined in the issuance profile
{{I-D.draft-mcguinness-oauth-mission}}, in particular Mission,
Mission Issuer (Authorization Server, the Mission `origin`), Resource
AS, Authority Set, the `mission` claim, `mission_id`, and the
`mission_resource_access` authorization details type. It additionally
uses:

Mission Status Response:
: A signed payload returned by the dedicated Mission Status operation
  ({{mission-status}}), reporting a Mission's current state and the
  audience-scoped evidence a consumer needs.

All JSON shown in this document is non-normative and illustrative; the
member definitions in the surrounding text are authoritative. HTTP
message examples follow the conventions of {{RFC9110}}; long URLs and
form parameters are wrapped for display. JWT and JWS examples are
shown as decoded JSON with separate header objects; on the wire the
JWS Compact Serialization {{RFC7515}} applies.

# Mission Status Operation {#mission-status}

This section is OPTIONAL. The issuance profile's stateless baseline
needs no dedicated status surface
({{I-D.draft-mcguinness-oauth-mission}}, Section "Mission Lifecycle and
Gating"); a deployment that does not stand up this operation, and a
consumer that does not use it, are unaffected.

The dedicated Mission Status operation is the canonical status surface
the issuance profile defers. Unlike token introspection
({{introspection-projection}}), which answers "is this
token's authorization still good," the Status operation answers "what
is the state of this Mission" keyed by the `mission_id` alone. Any
consumer holding a `mission_id` (including an auditor or a
cross-domain Resource AS) resolves it without holding a token the AS
issued.

The Mission Issuer publishes its Mission Status endpoint URL in
Authorization Server metadata ({{as-metadata}}) as
`mission_status_endpoint`, which a consumer resolves from a
credential's `mission.origin`. The endpoint MUST be served over TLS
1.2 or later (TLS 1.3 RECOMMENDED), following the recommendations of
{{RFC9325}}.

## Request {#mission-status-request}

The request is an HTTPS POST with an
`application/x-www-form-urlencoded` body containing:

`mission`:
: REQUIRED. A string. The canonical `mission_id`.

`audience`:
: REQUIRED. A string. The audience identifier of the
  requesting consumer.

`nonce`:
: REQUIRED. A string. A client-generated nonce binding the
  response to this request. It MUST be unique per request within the
  response lifetime; a consumer MUST reject a response whose `nonce`
  does not equal the one it sent. This is a standard client challenge:
  echoing it in the signed response anti-replay-binds that response to
  this specific request.

## Authentication {#mission-status-authentication}

The request MUST be authenticated. The AS MUST support, and the client
MUST use, exactly one of the following per request:

1. **mTLS client authentication** {{RFC8705}}. The AS validates the
   client's X.509 certificate against its configured trust anchors and
   the client's registered `tls_client_auth` metadata.
2. **DPoP-bound bearer token** {{RFC9449}}. The client presents a
   Mission-Status-scoped DPoP-bound token in the `Authorization`
   header with a `DPoP` proof header; the token's `cnf.jkt` MUST match
   the proof key thumbprint.
3. **Private-key-JWT client authentication** {{RFC7523}}. The client
   presents a signed JWT assertion as `client_assertion`.

Plain Basic or POST client authentication MUST NOT be used for this
endpoint. The AS MUST refuse a request not authenticated by one of the
three mechanisms with `unauthorized` (HTTP 401). Which mechanisms the
AS accepts is discovered through the AS's existing OAuth client-
authentication metadata {{RFC8414}}.

## Worked Request Example

~~~ http-message
POST /as/mission/status HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: DPoP eyJhbGciOiJFUzI1NiIsImtpZCI6...
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2Iiwi...

mission=msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-
&audience=https%3A%2F%2Ferp.example.com
&nonce=nonce_K9pV4nT2sR7mB1xQ
~~~

## Response {#mission-status-response}

On success the AS returns a JWS Compact Serialization {{RFC7515}}
signed with a key published in the AS's `jwks_uri`. The JWS header
carries `typ` of `mission-status-response+jwt` and a `kid` identifying
the signing key. Per {{RFC7515}} Section 4.1.9 the `typ` header omits
the `application/` prefix; the full media type
`application/mission-status-response+jwt` (registered in {{iana}}) is
used as the HTTP `Content-Type`.

{{RFC9701}} signed introspection responses are scoped to token
introspection and do not apply to a lookup keyed by `mission_id`; the
dedicated operation therefore uses a new media type and a JWS, not
{{RFC9701}} (see {{rfc-9701-vs-media-type}}). Implementations MUST NOT
use {{RFC9701}} for the dedicated operation.

The signed payload reports the Mission's current state and the
audience-scoped evidence the consumer needs.

~~~ http-message
HTTP/1.1 200 OK
Content-Type: application/mission-status-response+jwt
Cache-Control: no-store
Pragma: no-cache

eyJhbGciOiJFUzI1NiIsImtpZCI6InNhLWtleS0yMDI2LXEzIi...
~~~

Decoded JWS header:

~~~ json
{
  "alg": "ES256",
  "kid": "sa-key-2026-q3",
  "typ": "mission-status-response+jwt"
}
~~~

Decoded JWS payload:

~~~ json
{
  "iss": "https://as.example.com",
  "aud": "https://erp.example.com",
  "sub": "client_erp-recon-agent",
  "nonce": "nonce_K9pV4nT2sR7mB1xQ",
  "iat": 1797840000,
  "exp": 1797840060,
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "origin": "https://as.example.com",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ",
    "state": "active",
    "expires_at":     "2026-11-02T08:15:00Z",
    "mission_expiry": "2026-12-31T23:59:59Z"
  },
  "authorization_details": [
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["invoices.read", "journal-entries.write"] }
  ]
}
~~~

The members are:

- The signed JWT envelope `iss`, `aud`, `sub`, `nonce`, `iat`, `exp`.
  The `aud` is the response's audience binding and the `nonce` its
  request binding. `exp` bounds the validity of the signed response
  itself; how long the consumer MAY rely on the reported `state` is
  given separately by `mission.expires_at` below.
- `mission`: the `mission` object, the same shape as the `mission`
  claim of {{I-D.draft-mcguinness-oauth-mission}} (Section "The
  mission Claim") with status members added. It carries:
  - `id`, `origin`: the subject Mission's identifier and origin.
  - `authority_hash`: the issuance profile's consent commitment over
    the Authority Set ({{I-D.draft-mcguinness-oauth-mission}}, Section
    "Integrity Anchors").
  - `state`: the current Mission lifecycle state. With this extension
    the state space is `active`, `revoked`, `expired`
    ({{I-D.draft-mcguinness-oauth-mission}}, Section "Mission Lifecycle
    and Gating"), extended with `suspended` and `completed` when the
    Mission Lifecycle endpoint ({{mission-lifecycle-endpoint}}) is
    deployed.
  - `expires_at`: an {{RFC8259}} string giving the point until which
    the consumer MAY rely on the reported `state` without re-checking,
    governing caching ({{mission-status-caching}}). It is
    report-freshness metadata, carried in `mission` so it travels with
    `state` even on the introspection projection, which has no signed
    envelope to carry it ({{introspection-projection}}).
  - `mission_expiry`: the point at which the Mission itself expires
    ({{I-D.draft-mcguinness-oauth-mission}}).
- `authorization_details`: the audience-scoped Authority Set entries
  relevant to the requesting audience, as the `mission_resource_access`
  shape of {{I-D.draft-mcguinness-oauth-mission}} (Section "Mission
  Authority"), carried at the top level as a sibling of `mission` (as
  on the token and in the introspection response). Entries addressed
  to other audiences MUST NOT be disclosed.

A consumer MUST verify, before honoring a response:

1. the JWS signature against a current `jwks_uri` entry for the
   `origin` AS;
2. `iss` equals the expected AS issuer URL;
3. `aud` equals the consumer's own audience identifier;
4. `sub` equals the requesting client's identifier;
5. `nonce` equals the request's nonce; and
6. `iat` is not in the future and `exp` is not in the past, with up to
   30 seconds clock-skew tolerance.

## Caching {#mission-status-caching}

Consumers SHOULD cache a response keyed on (`mission_id`, audience)
until `mission.expires_at`. Consumers MUST NOT use a cached response
after `mission.expires_at`, with up to 30 seconds skew tolerance for
the `active` state only and no tolerance for terminal states.

## Anti-Oracle Property {#mission-status-anti-oracle}

A `mission_id` is never a bearer capability. The AS MUST authenticate
the requester and authorize it for the requested `mission_id` and
audience.

Unknown `mission_id` values and known-but-unauthorized references MUST
produce indistinguishable responses (HTTP 404 with a generic
not-found body; see {{mission-status-errors}}). The AS MUST NOT vary
response timing, payload size, or headers in a way that distinguishes
the two cases.

## Error Responses {#mission-status-errors}

Mission Status responses use the following symbols, mapped to HTTP
status codes. `ok`, `terminated`, and `suspended` are successful
outcomes returned with a signed Mission Status Response; the remaining
symbols are hard errors. The body of a hard error is a JSON object
{{RFC8259}}.

| Symbol | HTTP | Description |
|---|---|---|
| `ok` | 200 | Mission found and visible. |
| `unauthorized` | 401 | Request not authenticated. |
| `not_found` | 404 | Reference does not exist OR is not visible. |
| `terminated` | 200 | Mission is `revoked`, `completed`, or `expired`. |
| `suspended` | 200 | Mission is suspended. |
| `rate_limited` | 429 | Consumer is rate-limited. |
| `unavailable` | 503 | AS temporarily cannot serve status. |

Terminal and suspended states return HTTP 200 with the signed Mission
Status Response carrying `state`. Hard errors (`unauthorized`,
`not_found`, `rate_limited`, `unavailable`) return the matching HTTP
status with a JSON body. Note the distinction between the two access
failures: `unauthorized` (401) means the request carried no valid
authentication, whereas a request that is authenticated but not
authorized for the referenced Mission returns `not_found` (404), never
401, so that an unauthorized reference is indistinguishable from an
unknown one ({{mission-status-anti-oracle}}). The error body is:

~~~ http-message
HTTP/1.1 404 Not Found
Content-Type: application/json
Cache-Control: no-store

{
  "error": "not_found",
  "error_description":
    "Mission reference is not found or not visible.",
  "nonce": "nonce_K9pV4nT2sR7mB1xQ"
}
~~~

The body MUST contain `error`, `error_description`, and `nonce`, and
MUST NOT contain any member that would let a caller distinguish
unknown from unauthorized references. For `rate_limited`, the response
SHOULD include a `Retry-After` header {{RFC9110}} and a `retry_after`
body member in seconds.

# Token Introspection Mission Projection {#introspection-projection}

This section is OPTIONAL and is a thin delta over the OAuth 2.0 Token
Introspection {{RFC7662}} projection of
{{I-D.draft-mcguinness-oauth-mission}} (Section "Mission State via
Token Introspection"). That section already
defines a `mission` member on the introspection response carrying
`id`, `origin`, `authority_hash`, and (from the Mission origin) the
lifecycle `state`, together with the caller-authorization,
minimization, and origin-only-reports-state rules. This document does
not restate those rules.

This extension adds the following to that projection:

- An introspection response that carries a Mission projection is
  protected by TLS, as for token introspection generally
  ({{I-D.draft-mcguinness-oauth-mission}}, Section "Mission State via
  Token Introspection"). Where the projection's integrity and origin
  need to be verifiable independently of the transport (for example
  when the response transits intermediaries or is retained for audit),
  the AS SHOULD return it as a {{RFC9701}}-signed response, advertised
  through the standard `introspection_signing_alg_values_supported`
  metadata {{RFC8414}}.
- When the responding AS is the Mission origin, the projection MAY
  additionally carry `expires_at`, an {{RFC8259}} string giving the
  point until which the consumer MAY rely on the reported `state`
  without re-checking, governed by the caching rule of
  {{mission-status-caching}}. When `expires_at` is absent (for example
  a non-origin projection), the consumer MUST NOT cache the reported
  `state` across requests and re-checks per use or relies on the
  token's own lifetime.

This projection and the dedicated Mission Status Response
({{mission-status-response}}) carry Mission facts in a `mission` object
of the same shape: the open `mission` claim object of
{{I-D.draft-mcguinness-oauth-mission}} (Section "The mission Claim")
with status members (`state`, `expires_at`, and, on the dedicated
response, `mission_expiry`) added. This
projection populates the subset a token-holding consumer needs; the
dedicated response populates more. Either way a consumer reads the
same fact from the same place.

Example {{RFC9701}}-signed introspection response (decoded payload),
for a token whose Mission is `active`:

~~~ json
{
  "iss":     "https://as.example.com",
  "aud":     "https://erp.example.com",
  "iat":     1797840000,
  "exp":     1797840060,
  "active":  true,
  "client_id": "s6BhdRkqt3",
  "sub":     "user_3p2q8mN1a0kV7tR",
  "scope":   "openid",
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "origin": "https://as.example.com",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ",
    "state":   "active",
    "expires_at": "2026-11-02T08:15:00Z"
  }
}
~~~

A consumer holding only a `mission_id`, or one that needs signed
evidence independent of a specific token (an auditor or a cross-domain
Resource AS), uses the dedicated Mission Status operation
({{mission-status}}); the introspection projection is purely a
same-call convenience for token-holding consumers and is never the
sole Mission Status path.

# Mission Lifecycle Endpoint {#mission-lifecycle-endpoint}

This section is OPTIONAL. The issuance profile lets the Subject,
Approver, or an administrator revoke a Mission by an authenticated,
deployment-defined means and defers a standardized management API and
the richer `suspend`, `resume`, and `complete` operations
({{I-D.draft-mcguinness-oauth-mission}}, Section "Revocation"). This
section standardizes that management surface.

The AS publishes its Mission Lifecycle endpoint URL in Authorization
Server metadata ({{as-metadata}}) as `mission_lifecycle_endpoint`,
distinct from {{RFC7009}} token revocation. The endpoint MUST be
served over TLS 1.2 or later (TLS 1.3 RECOMMENDED), following the
recommendations of {{RFC9325}}.

Adopting this endpoint extends the issuance profile's lifecycle state
space ({{I-D.draft-mcguinness-oauth-mission}}, Section "Mission
Lifecycle and Gating") with two additional states: `suspended` (a
non-terminal paused Mission that derives no tokens until resumed) and
`completed` (a terminal state recording successful completion).
Issuance gating treats any state other than `active` as
non-deriving, exactly as the base profile gates on `active`.

## Operations

The endpoint accepts authenticated POST requests with a
form-urlencoded body:

`mission`:
: REQUIRED. A string. The canonical `mission_id`.

`operation`:
: REQUIRED. A string. One of `revoke`, `suspend`,
  `resume`, `complete`.

`reason`:
: OPTIONAL. A string. A human-readable reason recorded in
  audit, maximum 1024 characters.

`nonce`:
: REQUIRED. A string. A client-generated nonce.

The operations are:

- `revoke`: terminate the Mission; transition to `revoked`.
- `suspend`: pause the Mission; transition to `suspended`.
- `resume`: return a suspended Mission to `active`.
- `complete`: mark the Mission completed; transition to `completed`.

## Authentication

The lifecycle endpoint uses the same authentication mechanisms as the
Mission Status endpoint ({{mission-status-authentication}}): mTLS,
DPoP-bound bearer, or private-key JWT, discovered through the AS's
existing OAuth client-authentication metadata {{RFC8414}}.

## Authorization

The AS authorizes lifecycle operations against deployment policy; this
document does not standardize the policy. Typical deployments
authorize `revoke` to the Mission's Subject or Approver and to
administrators; `suspend` and `resume` to administrators; and
`complete` to the requesting client or an administrator.

The AS MUST refuse an unauthorized lifecycle request with the
not-found response shape of {{mission-status-errors}}, so the endpoint
does not act as a Mission enumeration oracle.

## Worked Example

Revoke request:

~~~ http-message
POST /as/mission/lifecycle HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: DPoP eyJhbGciOiJFUzI1NiIsImtpZCI6...
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2Iiwi...

mission=msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-
&operation=revoke
&reason=Quarterly+reconcile+completed+early
&nonce=nonce_8Y3vN0sM6tP1xR9bQ5
~~~

Revoke success response: the AS returns the updated status as a signed
Mission Status Response ({{mission-status-response}}). Because the
Lifecycle request carries no `audience`, the AS sets `aud` to the
authenticated requester and MAY omit `authorization_details` (a
lifecycle confirmation reports `state`, not audience-scoped authority);
`sub` is the authenticated requesting client, as for any Mission Status
Response, while the human actor behind the operation is recorded only
in the audit log.

~~~ http-message
HTTP/1.1 200 OK
Content-Type: application/mission-status-response+jwt
Cache-Control: no-store

eyJhbGciOiJFUzI1NiIsImtpZCI6InNhLWtleS0yMDI2LXEzIi...
~~~

Decoded JWS payload:

~~~ json
{
  "iss": "https://as.example.com",
  "aud": "https://erp.example.com",
  "sub": "client_erp-recon-agent",
  "nonce": "nonce_8Y3vN0sM6tP1xR9bQ5",
  "iat": 1797843200,
  "exp": 1797843260,
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "origin": "https://as.example.com",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ",
    "state": "revoked",
    "expires_at":     "2026-11-02T09:11:40Z",
    "mission_expiry": "2026-12-31T23:59:59Z"
  }
}
~~~

The AS records the operation, actor, time, and any `reason` in its
audit log; the response confirms the outcome through the updated
`state`.

## Idempotency

Lifecycle operations MUST be idempotent on the pair (`mission`,
`operation`). A repeated request that does not change state returns
success without side effect, returning the current Mission Status
Response.

## Relationship to RFC 7009

A Mission revocation through this endpoint cascades to credentials
derived from the Mission per the AS's advertised revocation
propagation ({{revocation-enforcement-classes}}). The AS MAY additionally invoke
{{RFC7009}} token revocation for specific outstanding tokens when it
knows their `jti`. {{RFC7009}} alone does NOT revoke a Mission; the
lifecycle endpoint is the authoritative Mission state change.

# Revocation Propagation {#revocation-enforcement-classes}

This section is OPTIONAL. The issuance profile bounds outstanding
self-contained tokens by their lifetime and OPTIONAL token
introspection ({{I-D.draft-mcguinness-oauth-mission}}, Section
"Revocation"). A deployment that needs a Mission state change to take
effect faster than token lifetime alone combines the propagation
mechanisms this suite offers and sizes token lifetimes to match.

The mechanisms are each discovered from their own metadata, not from a
separate posture list:

- consulting Mission state at each derivation event (the token
  endpoint, refresh, Token Exchange), the issuance profile's
  always-present baseline, which does not invalidate already-issued
  self-contained tokens;
- token introspection ({{introspection-projection}}), which returns
  `active: false` for a token whose Mission state disallows use even
  before the token expires, discovered from `introspection_endpoint`
  and `introspection_signing_alg_values_supported`;
- the Mission Status operation ({{mission-status}}) for per-request
  state checks by high-assurance Resource Servers, discovered from
  `mission_status_endpoint`; and
- event-driven propagation of state changes over a Shared Signals
  stream ({{I-D.draft-mcguinness-oauth-mission-signals}}), discovered
  from `mission_event_stream_endpoint`.

A deployment advertises `mission_max_stale_seconds` ({{as-metadata}}),
the maximum interval it tolerates for a Mission state change to take
effect, so a consumer can size token lifetimes and choose propagation
mechanisms to match.

## Recommended Access-Token TTL

Where Mission revocation must take effect but only the baseline
derivation-time check is in use, Mission-bound access tokens SHOULD use
TTLs no longer than the declared `mission_max_stale_seconds`.
Deployments where revocation propagates out of band (token
introspection, per-request status checks, or the event stream) MAY use
longer TTLs.

# Authorization Server Metadata {#as-metadata}

This section is OPTIONAL and applies only to a deployment that adopts
one or more of the extensions above. An AS advertises the surfaces it
supports through the following members of its Authorization Server
metadata document {{RFC8414}}, in addition to the issuance profile's
`mission_bound_authorization_supported`
({{I-D.draft-mcguinness-oauth-mission}}, Section "Authorization Server
Metadata"). Unlike the issuance profile, which advertises only that
boolean, this document defines OAuth AS metadata members for the
endpoints and classes it introduces, so a consumer discovers them
through standard {{RFC8414}} discovery.

`mission_status_endpoint`:
: OPTIONAL. A string containing a URL. The URL of the
  dedicated Mission Status operation ({{mission-status}}). Present
  when the AS supports it.

`mission_lifecycle_endpoint`:
: OPTIONAL. A string containing a URL. The URL of the
  Mission Lifecycle endpoint ({{mission-lifecycle-endpoint}}). Present
  when the AS supports it.

`mission_max_stale_seconds`:
: OPTIONAL. An integer. The maximum
  tolerated interval, in seconds, for revocation propagation
  ({{revocation-enforcement-classes}}).

DPoP and mTLS support for issued credentials are read from the
standard `dpop_signing_alg_values_supported` {{RFC9449}} and
`tls_client_certificate_bound_access_tokens` {{RFC8705}} metadata;
this document defines no separate sender-constraint member. When the
introspection projection ({{introspection-projection}}) is signed, the
signing is discovered through the standard
`introspection_signing_alg_values_supported` metadata.

## Worked Metadata Example

A discovery response from
`https://as.example.com/.well-known/oauth-authorization-server`,
showing the issuance profile members plus the extension members of
this document:

~~~ http-message
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: max-age=3600

{
  "issuer": "https://as.example.com",
  "token_endpoint": "https://as.example.com/as/token",
  "introspection_endpoint":
    "https://as.example.com/as/introspect",
  "jwks_uri":
    "https://as.example.com/.well-known/jwks.json",
  "introspection_signing_alg_values_supported": ["ES256"],
  "mission_bound_authorization_supported": true,

  "mission_status_endpoint":
    "https://as.example.com/as/mission/status",
  "mission_lifecycle_endpoint":
    "https://as.example.com/as/mission/lifecycle",
  "mission_max_stale_seconds": 60
}
~~~

# Security Considerations {#security-considerations}

The security considerations of the issuance profile
{{I-D.draft-mcguinness-oauth-mission}} apply in full. This section
covers threats specific to the extensions defined here.

## Mission Status Enumeration

Per the anti-oracle property ({{mission-status-anti-oracle}}), the AS
MUST NOT let a caller distinguish an unknown `mission_id` from a
known-but-unauthorized one at the Status or Lifecycle endpoint. The
error shape of {{mission-status-errors}} mitigates this by requiring
identical body content, identical HTTP status, and timing- and
size-invariance between the two cases. An implementation that leaks
the distinction exposes the Mission space to enumeration.

## Mission Status Response Replay

A Mission Status Response is bound to (caller `sub`, audience,
`nonce`, issuance time). Replay against a different caller or audience,
or beyond `mission.expires_at`, is detectable by signature
verification and by verifying the bindings; a consumer MUST verify all
six checks of {{mission-status-response}} before honoring a response. A
response cached and replayed by the same caller within
`mission.expires_at` is equivalent to a fresh response; a consumer MUST
NOT use a cached response after `mission.expires_at`, with the skew
tolerance of {{mission-status-caching}}.

## Mission Status Denial of Service

The Status endpoint is on the consumption path of every Mission-bound
credential validation in deployments where consumers query Mission
Status per request.
The AS MUST implement per-consumer rate limiting (returning
`rate_limited`, {{mission-status-errors}}) and SHOULD encourage
consumer-side caching ({{mission-status-caching}}) to reduce traffic.

## RFC 9701 vs. New Media Type {#rfc-9701-vs-media-type}

When the introspection projection is signed
({{introspection-projection}}), it uses {{RFC9701}}, which is scoped to
token introspection. The dedicated Mission Status operation uses a new
media type (`application/mission-status-response+jwt`, {{iana}}) and a
JWS {{RFC7515}}, because {{RFC9701}} does not apply to a lookup keyed by
`mission_id`. Implementations MUST NOT use {{RFC9701}} for the
dedicated operation, and MUST NOT accept an unsigned response from the
dedicated Mission Status operation in place of the signed form it
requires.

## Signing-Key Retention for Audit

The AS signs Mission Status and Lifecycle responses with a key from
its `jwks_uri`. The AS MUST retain the public JWK for every `kid` it
has signed such a response under, indexed by `kid`, for at least the
Mission record retention period (even after the key is rotated out
of the live `jwks_uri`), so an archived
`application/mission-status-response+jwt` remains verifiable for audit
and dispute. The AS MAY expose retired verification keys through a
deployment-defined audit interface but MUST NOT serve them as active
keys at `jwks_uri`.

## General OAuth Security

This document inherits OAuth 2.0 Best Current Practice {{RFC9700}} for
the OAuth surfaces it composes with; implementers MUST follow current
OAuth security guidance.

# Privacy Considerations {#privacy-considerations}

The privacy considerations of the issuance profile
{{I-D.draft-mcguinness-oauth-mission}} apply in full. This section
covers privacy specific to the extensions here.

## Status and Lifecycle as Disclosure Surfaces

The Mission Status operation ({{mission-status}}) and the
introspection projection ({{introspection-projection}}) disclose
Mission state, the
`authority_hash`, and the audience-scoped `authorization_details` to
the authenticated, authorized requester. A deployment MUST treat both
as Mission information-disclosure surfaces with the same privacy
posture, audience-filtering the disclosed authority so a consumer
never sees entries addressed to other audiences
({{mission-status-response}}).

## Status Audit Logging

The AS records Status and Lifecycle requests (containing
`mission_id`, audience, caller, and timing) in audit logs.
Deployments MUST treat these logs as PII sinks per the issuance
profile's privacy considerations.

# Conformance {#conformance}

An implementation conforms to the issuance profile
{{I-D.draft-mcguinness-oauth-mission}} first. Each extension in this
document is independently OPTIONAL; an implementation names the ones it
supports (for example, "issuance profile with Mission Status and
Mission Lifecycle"), and an implementation that supports none of them
is still a conforming issuance profile.

An implementation claiming an extension MUST meet its requirements:

- **Mission Status**: serve the dedicated Mission Status operation
  ({{mission-status}}) with JWS-signed responses
  (`application/mission-status-response+jwt`), the authentication of
  {{mission-status-authentication}}, the anti-oracle property
  ({{mission-status-anti-oracle}}), and the error shape of
  {{mission-status-errors}}; and advertise `mission_status_endpoint`.
- **Introspection projection**: carry the Mission projection on the
  introspection response ({{introspection-projection}}), returning it
  as a {{RFC9701}}-signed response where end-to-end integrity is
  required.
- **Mission Lifecycle**: serve the management endpoint
  ({{mission-lifecycle-endpoint}}), gate the `suspended` and
  `completed` states it introduces exactly as the base profile gates
  on non-`active` state, and advertise `mission_lifecycle_endpoint`.
- **Revocation propagation**: advertise `mission_max_stale_seconds`
  and size Mission-bound access-token TTLs to it
  ({{revocation-enforcement-classes}}).

# IANA Considerations {#iana}

This document requests IANA actions for OAuth AS metadata members and
a media type. It defines no new registry: the authentication-method
value space is a closed set defined inline.

## OAuth Authorization Server Metadata Registration

IANA is requested to register the following in the "OAuth
Authorization Server Metadata" registry {{RFC8414}}. For each:
Change Controller IETF; Reference this document, {{as-metadata}}.

- `mission_status_endpoint`
- `mission_lifecycle_endpoint`
- `mission_max_stale_seconds`

## Media Type Registration

IANA is requested to register one media type per {{RFC6838}}.

### application/mission-status-response+jwt

- Type name: application
- Subtype name: mission-status-response+jwt
- Required parameters: none
- Optional parameters: none
- Encoding considerations: binary; JWS Compact Serialization
- Security considerations: see {{security-considerations}}
- Interoperability considerations: see this document
- Published specification: this document
- Applications that use this media type: OAuth Mission-Bound consumers
- Fragment identifier considerations: not applicable
- Restrictions on usage: none
- Provisional registration: no
- Magic number(s): none
- File extension(s): none
- Macintosh file type code(s): none
- Person & email address to contact: Karl McGuinness
  <public@karlmcguinness.com>
- Intended usage: COMMON
- Author/Change controller: IETF

## Well-Known URI

This document registers no new Well-Known URI. The metadata members of
{{as-metadata}} are added to the OAuth Authorization Server Metadata
document at `/.well-known/oauth-authorization-server` {{RFC8414}}.

# Acknowledgments
{:numbered="false"}

The author thanks the implementers and reviewers of the Mission-Bound
Authorization work for feedback that shaped these extensions.

--- back
