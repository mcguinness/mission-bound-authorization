---
title: "Mission Status and Lifecycle for OAuth 2.0"
abbrev: "OAuth Mission Status"
category: std

docname: draft-mcguinness-oauth-mission-status-latest
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
 - status
 - lifecycle
 - revocation
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-status.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC3339:
  RFC6838:
  RFC7009:
  RFC7515:
  RFC7523:
  RFC7662:
  RFC8259:
  RFC8414:
  RFC8693:
  RFC8705:
  RFC9068:
  RFC9325:
  RFC9449:
  RFC9701:
  RFC9728:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

informative:
  RFC8725:
  RFC9110:
  RFC9457:
  RFC9700:
  I-D.draft-mcguinness-oauth-mission-resource-access:
    title: "Mission Resource Access Profile for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-resource-access.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-status-list:
    title: "Mission Status List for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-status-list.html
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
  I-D.draft-mcguinness-oauth-mission-child-delegation:
    title: "Mission Child Delegation for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-child-delegation.html
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
  I-D.draft-mcguinness-mission-runtime:
    title: "Mission-Bound Runtime Enforcement"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-runtime.html
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
  I-D.draft-mcguinness-oauth-mission-management:
    title: "Mission Management for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-management.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-authority-server:
    title: "Mission Authority Server"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-authority-server.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-aauth:
    title: "Mission Context Binding for AAuth"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-aauth.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-mandate:
    title: "Mission Mandate"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-mandate.html
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

--- abstract

The Mission-Bound Authorization for OAuth 2.0 profile binds issued
authority to a durable, human-approved Mission and gates issuance on
Mission state, but it observes Mission state only through token lifetime
and optional token introspection. This document
defines the Mission state-management surfaces it defers: the Mission
Status operation (keyed by `mission_id`) with signed responses, the
Mission projection for token introspection, the Mission Lifecycle
endpoint with `revoke`, `suspend`, `resume`, and `complete`
operations, the `suspended` and `completed` states with the consolidated
lifecycle state machine this profile owns, and revocation-propagation
guidance. It defines an extension point through which a companion
profile MAY add a fleet-scale Mission Status List or an entry-grain
`discharge` operation without altering this profile's own surfaces.
Each capability is independently optional; an implementation can adopt
any subset, and one that adopts none remains a conforming issuance
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
Mission state. It names this profile for the canonical Mission Status
surface (keyed by `mission_id`) and its signed status evidence, and
defers a standardized management endpoint for lifecycle transitions to
this document.

This document specifies those surfaces as optional extensions
that build on the issuance profile. The capabilities are:

- A dedicated **Mission Status operation**
  ({{mission-status}}), which any consumer holding a `mission_id`
  resolves, with responses signed as a JWS {{RFC7515}}.
- An extension to OAuth token introspection that carries a Mission
  projection, which a deployment MAY return as a {{RFC9701}}-signed
  response ({{introspection-projection}}).
- A **Mission Lifecycle endpoint** ({{mission-lifecycle-endpoint}})
  for explicit `revoke`, `suspend`, `resume`, and `complete`
  operations, distinct from {{RFC7009}} token revocation, with an
  extension point through which a companion profile MAY register a
  further `operation` value, such as the Entry Discharge companion's
  `discharge` ({{I-D.draft-mcguinness-oauth-mission-discharge}}).
- A fleet-scale **Mission Status List** extension point, profiled by
  the Status List companion
  ({{I-D.draft-mcguinness-oauth-mission-status-list}}).
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

This document does not restate the issuance profile. The Mission Intent,
authority derivation, the `mission` claim, the integrity anchors,
Mission-bound token issuance, the subset rule, and lifecycle gating are
all defined in {{I-D.draft-mcguinness-oauth-mission}}; the
`mission_resource_access` authorization details type is defined in its
Mission Resource Access Profile
({{I-D.draft-mcguinness-oauth-mission-resource-access}}); both are
referenced, not re-specified, here.

# Status: An Optional Profile {#doc-status}

<!-- family-status: BEGIN (generated from family-manifest.json; exact-matched by scripts/check-family-manifest.mjs) -->
Role: companion. Spec maturity: experimental. Maintenance: active.
Implementation: 4 conformance rows in conformance-manifest.json (2 tested, 2 todo).
Adopt when: You must observe or change Mission state beyond token expiry (revoke, suspend, complete).
Requires: Mission-Bound Authorization for OAuth 2.0.
<!-- family-status: END -->

# Conventions and Terminology {#conventions-and-definitions}

{::boilerplate bcp14-tagged}

This document uses the terms defined in the issuance profile
{{I-D.draft-mcguinness-oauth-mission}}, in particular Mission,
Mission Issuer (the Mission `issuer`: in this document's OAuth binding
the Authorization Server; a standalone Mission Issuer, the Mission
Authority Server {{I-D.draft-mcguinness-mission-authority-server}},
serves these surfaces with the same semantics; the AAuth Person
Server plays the same role for its native missions through its own
AAuth-native management surface
{{I-D.draft-mcguinness-mission-aauth}}), Authority Set, the
`mission` claim, and `mission_id`; and the `mission_resource_access`
authorization details type defined in its Mission Resource Access
Profile ({{I-D.draft-mcguinness-oauth-mission-resource-access}}).
Resource AS is used as defined in the
cross-domain companion
{{I-D.draft-mcguinness-oauth-mission-cross-domain}}. It additionally
uses:

Mission Status Response:
: A signed payload returned by the dedicated Mission Status operation
  ({{mission-status}}), reporting a Mission's current state and the
  audience-scoped evidence a consumer needs.

Discharge:
: The state of a `mission_resource_access` entry whose `terminal_when`
  completion condition has been met, as defined by the Entry
  Discharge companion
  ({{I-D.draft-mcguinness-oauth-mission-discharge}}). A discharged
  entry's authority is spent: it is no longer derivable.

Effective Authority Set:
: The approved Authority Set after applying every issuer-held,
  monotonic narrowing mechanism the deployment runs. Where the Entry
  Discharge companion is adopted, it contributes discharged entries
  ({{I-D.draft-mcguinness-oauth-mission-discharge}}). Each other
  narrowing profile defines its own subtraction. No narrowing
  mechanism adds or restores authority. Membership in this set is
  necessary, never sufficient, for an action to proceed: the runtime
  decision evaluates it alongside every other required decision input
  ({{I-D.draft-mcguinness-mission-runtime}}).

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
token's authorization still good," the Mission Status operation answers
"what is the state of this Mission" keyed by the `mission_id` alone. Any
consumer holding a `mission_id` (including an auditor or a
cross-domain Resource AS) resolves it without holding a token the AS
issued.

The Mission Issuer publishes its Mission Status endpoint URL in
Authorization Server metadata ({{as-metadata}}) as
`mission_status_endpoint`, which a consumer resolves from a
credential's `mission.issuer`. The endpoint MUST be served over TLS
1.2 or later (TLS 1.3 RECOMMENDED), following the recommendations of
{{RFC9325}}.

## Request {#mission-status-request}

The request is an HTTPS POST with an
`application/x-www-form-urlencoded` body containing:

`mission_id`:
: REQUIRED. A string. The canonical Mission Identifier, named per the
  issuance profile's external-surface convention
  ({{I-D.draft-mcguinness-oauth-mission}}).

`audience`:
: CONDITIONAL. A string. The audience identifier of the
  requesting consumer. An authorized non-RS consumer (for example an
  auditor or a cross-domain Resource AS) that needs only Mission state,
  not audience-scoped authority, MAY omit `audience`; the response is
  then state-only and carries no `authorization_details`
  ({{mission-status-response}}). A Resource Server resolving authority
  for a specific audience MUST send it.

`nonce`:
: REQUIRED. A string. A client-generated nonce binding the
  response to this request. It MUST be unique per request within the
  response lifetime. A consumer MUST reject a response whose `nonce`
  does not equal the one it sent. This is a standard client challenge:
  echoing it in the signed response anti-replay-binds that response to
  this specific request.

## Authentication {#mission-status-authentication}

The request MUST be authenticated. The AS MUST support at least one
of the following mechanisms. The client MUST use exactly one of them
per request:

1. **mTLS client authentication** {{RFC8705}}. The AS validates the
   client's X.509 certificate against its configured trust anchors and
   the client's registered `tls_client_auth` metadata.
2. **Sender-constrained access token**. The client presents a
   `mission_status`-scoped access token (see the authorization
   requirement below) in the `Authorization` header, sender-constrained
   either by DPoP {{RFC9449}} (the `DPoP` scheme with a `DPoP` proof
   header, the token's `cnf.jkt` matching the proof key thumbprint) or
   by mTLS {{RFC8705}} (a certificate-bound token, the `Bearer` scheme,
   whose `cnf.x5t#S256` matches the presented client certificate). The
   token MUST be audience-restricted to this endpoint's
   protected-resource identifier (below).
3. **Private-key-JWT client authentication** {{RFC7523}}. The client
   presents `client_assertion_type` with the exact value
   `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and a signed
   JWT as `client_assertion`. The assertion's `aud` MUST name the URL of
   the endpoint being invoked (the `mission_status_endpoint` for a
   Status request, the `mission_lifecycle_endpoint` for a Lifecycle
   request), not the token endpoint; the AS MUST reject an assertion
   whose `aud` names no such endpoint. The AS accepts only the JWS
   {{RFC7515}} algorithms it advertises for that endpoint
   ({{as-metadata}}); `none` MUST NOT be used.

Plain Basic or POST client authentication MUST NOT be used for this
endpoint. The AS MUST refuse a request not authenticated by one of the
three mechanisms with `unauthorized` (HTTP 401). The mechanism is
determined by wire evidence in order: a request presenting an access
token in `Authorization` is mechanism 2, and any client certificate is
then evaluated only as that token's mTLS sender constraint; otherwise a
request presenting `client_assertion` is mechanism 3, and any client
certificate is not treated as client authentication; otherwise a request
presenting only a client certificate is mechanism 1. This order keeps
"exactly one mechanism" satisfiable when mTLS terminates at the edge.

An authenticated caller MUST additionally carry an explicit read
authorization: a `mission_status` scope on the presented access token,
or a deployment-defined equivalent grant bound to the authenticated
client. The `mission_status` scope authorizes the Mission Status read
operation and mirrors the `mission_lifecycle` scope of the Mission
Lifecycle endpoint ({{mission-lifecycle-endpoint}}). The token-less
path is preserved: a consumer that holds only a `mission_id` and
authenticates directly as a client (mechanism 1 or 3) carries the
deployment-defined equivalent grant, not a scope, and so resolves
Mission state without holding an access token the AS issued. A caller
carrying no such authorization is refused with the not-found response
of {{mission-status-errors}} ({{mission-status-anti-oracle}}).

A presented access token (mechanism 2) MUST be audience-restricted to
this endpoint's protected-resource identifier: the `resource` value the
AS publishes for this endpoint in its Protected Resource Metadata
{{RFC9728}}. For these surfaces that identifier is the endpoint's own URL
(the `mission_status_endpoint` or `mission_lifecycle_endpoint`), so the
mechanism-2 access-token audience and the mechanism-3 private-key-JWT
`aud` name the same value. The AS MUST reject a token whose audience does
not name that identifier. This token audience is distinct from the request body's
`audience` parameter ({{mission-status-request}}): the token audience
authorizes the call at this endpoint, whereas the request `audience`
carries no authentication weight and only selects the
Resource-Server-specific authority projection the response returns
({{mission-status-response}}).

Which mechanisms and authorization this endpoint accepts are
discoverable per endpoint, not inferred from the token endpoint's
metadata. The AS advertises the methods this endpoint accepts in
`mission_status_endpoint_auth_methods_supported` ({{as-metadata}}).

For
the sender-constrained access-token path, this endpoint is an OAuth
protected resource: the AS publishes, in its Protected Resource Metadata
for this resource {{RFC9728}}, the `resource` identifier the token's
audience MUST name, the `mission_status` scope it requires
(`scopes_supported`), and the presentation and sender constraints it
accepts (`bearer_methods_supported`, `dpop_bound_access_tokens_required`,
`tls_client_certificate_bound_access_tokens`). For the retained
direct-client-authentication path (mTLS {{RFC8705}} or private-key JWT
{{RFC7523}}), the accepted methods and, for `private_key_jwt`, the
accepted client-assertion signing algorithms are advertised for this
endpoint ({{as-metadata}}), not read from the token endpoint's
`token_endpoint_auth_methods_supported` {{RFC8414}}. Both paths are
therefore discoverable.

## Worked Request Example

~~~ http-message
POST /as/mission/status HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: DPoP eyJhbGciOiJFUzI1NiIsImtpZCI6...
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2Iiwi...

mission_id=msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-
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
used as the HTTP `Content-Type`. Exact validation of the protected
`typ` value, together with mutually exclusive validation rules for
the artifact profiles, implements the substitution defense of
{{RFC8725}}, Sections 3.11 and 3.12.

{{RFC9701}} signed introspection responses are scoped to token
introspection and do not apply to a lookup keyed by `mission_id`; the
dedicated Mission Status operation therefore uses a new media type and a
JWS, not {{RFC9701}} (see {{rfc-9701-vs-media-type}}). Implementations
MUST NOT use {{RFC9701}} for the dedicated Mission Status operation.

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
  "iat": 1793606400,
  "exp": 1793606460,
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "issuer": "https://as.example.com",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ",
    "state": "active",
    "version": 4,
    "expires_at":  "2026-12-31T23:59:59Z",
    "fresh_until": "2026-11-02T08:00:45Z"
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
  request binding. When the request omitted `audience`
  ({{mission-status-request}}), the response is state-only and the AS
  MUST set `aud` to the authenticated requester's identifier, as the
  Lifecycle endpoint does ({{mission-lifecycle-endpoint}}); the
  consumer's `aud` verification below then checks that identifier. `exp` bounds the validity of the signed response
  itself; how long the consumer MAY rely on the reported `state` is
  given separately by `mission.fresh_until` below.
- `mission`: the `mission` object, the same shape as the `mission`
  claim of {{I-D.draft-mcguinness-oauth-mission}} (Section "The
  Mission Claim") with status members added. It carries:
  - `id`, `issuer`: the subject Mission's identifier and issuer.
  - `authority_hash`: OPTIONAL. The issuance profile's consent
    commitment over the Authority Set ({{I-D.draft-mcguinness-oauth-mission}},
    Section "Integrity Anchors"), disclosed at the AS's discretion to
    a caller it authorizes for audit or correlation use, on the same
    minimization footing as the issuance profile's introspection
    disclosure privilege ({{I-D.draft-mcguinness-oauth-mission}},
    Section "Caller Authorization and Minimization"). Not carried on
    the issuance profile's baseline `mission` claim.
  - `state`: the current Mission lifecycle state. The authoritative
    state space is the issuance profile's
    ({{I-D.draft-mcguinness-oauth-mission}}, Section "Mission Lifecycle
    and Gating"): the issuance profile states `active`, `revoked`, `expired`, this
    profile's `suspended` and `completed` when the Mission Lifecycle
    endpoint ({{mission-lifecycle-endpoint}}) is deployed, and any
    further state a companion profile defines and the deployment runs
    (for example `superseded`, defined by the Mission Expansion profile
    ({{I-D.draft-mcguinness-oauth-mission-expansion}}) for an expanded
    predecessor, or `cascaded`, defined by the Mission Child Delegation
    profile ({{I-D.draft-mcguinness-oauth-mission-child-delegation}})
    for a cascade-terminated Child Mission). A consumer applies the
    issuance profile's forward-compatibility rule: only `active` permits
    reliance, and every other value, recognized or not, is non-active.
    This profile's reliance behavior does not depend on recognizing
    these companion-defined states; the fail-safe rule above governs.
  - `expires_at`: the point at which the Mission itself expires, the
    Mission record's `expires_at`
    ({{I-D.draft-mcguinness-oauth-mission}}).
  - `fresh_until`: an RFC 3339 {{RFC3339}} date-time giving the point
    until which the consumer MAY rely on the reported `state` without
    re-checking, governing caching ({{mission-status-caching}}). It is
    report-freshness metadata, carried in `mission` so it travels with
    `state` even on the introspection projection, which has no signed
    envelope to carry it ({{introspection-projection}}).
  - `suspend_until`, `on_expiry`: CONDITIONAL. Present only while the
    Mission is `suspended` under a deadline
    ({{mission-lifecycle-endpoint}}): the RFC 3339 {{RFC3339}}
    deadline, and the transition (`resume` or `revoke`) the AS applies
    when it passes.
  - `successor`: OPTIONAL. A string, the successor `mission_id`. Present
    only when `state` is `superseded`, giving the successor that
    replaced this Mission, set atomically at supersession on the
    predecessor's record
    ({{I-D.draft-mcguinness-oauth-mission-expansion}}).
  - `carried_to`: CONDITIONAL string. A deployment implementing Child Mission
    Carryover MUST include the committed replacement Mission identifier when
    reporting the old child's `cascaded` state, and MUST omit it when no
    replacement was committed. It is same-issuer correlation, not authority
    ({{I-D.draft-mcguinness-oauth-mission-child-delegation}}, Section
    "Carryover Evidence and Observation").
  - `version`: REQUIRED. The Mission's **state version**: a strictly
    monotonic per-Mission counter the Mission Issuer maintains,
    incremented on each committed lifecycle transition (the approval
    event is version 1) and each committed metadata-only change,
    current as of the reported `state`. It orders observations of one
    Mission across every surface: an event consumer that
    re-established state through this operation re-seats its gap
    detection on it (the last-applied Signals version becomes this
    value, {{I-D.draft-mcguinness-oauth-mission-signals}}), a
    lifecycle mutation can guard on it ({{idempotency}}), and a
    materialized policy view names the value it materialized
    ({{I-D.draft-mcguinness-mission-runtime}}).
  - Extension members: a companion profile MAY add further members to
    this object. For example, the Status List companion adds a
    `status_list` reference where the deployment publishes a Mission
    Status List
    ({{I-D.draft-mcguinness-oauth-mission-status-list}}).
- `authorization_details`: the Authority Set entries of every
  AS-supported `authorization_details` type
  ({{I-D.draft-mcguinness-oauth-mission}}, Section "Authorization
  Details Types") relevant to the requesting audience, audience
  relevance determined per each entry's own type specification (for
  the general-purpose `mission_resource_access` type, by its
  `resource` member,
  {{I-D.draft-mcguinness-oauth-mission-resource-access}}), carried at
  the top level as a sibling of `mission` (as on the token and in the
  introspection response). Entries addressed to other audiences MUST
  NOT be disclosed. When the request omits `audience`
  ({{mission-status-request}}), there is no requesting audience: the
  response is state-only and MUST NOT carry `authorization_details`.

A consumer MUST verify, before honoring a response:

1. the JWS header `typ` is `mission-status-response+jwt`;
2. the JWS header `alg` is one the AS advertises in
   `mission_status_signing_alg_values_supported` ({{as-metadata}}),
   rejecting `none` and any algorithm not listed;
3. the JWS signature against a current `jwks_uri` entry for the
   `issuer` AS;
4. `iss` equals the expected AS issuer URL;
5. `aud` equals the consumer's own audience identifier;
6. `sub` equals the requesting client's identifier;
7. `nonce` equals the request's nonce;
8. `mission.id` equals the requested `mission_id`; and
9. `iat` is not in the future and `exp` is not in the past, with up to
   30 seconds clock-skew tolerance.

## Caching {#mission-status-caching}

Caching follows these rules:

- **Cache key.** Consumers SHOULD cache a response keyed on
  (`mission_id`, audience), or on (`mission_id`, requester
  identifier) for a state-only response, until `mission.fresh_until`.
- **Hard stop.** Consumers MUST NOT use a cached response after
  `mission.fresh_until`. In particular, a consumer MUST NOT extend
  reliance on a cached `suspended` (or any non-`active`) response
  beyond `mission.fresh_until`.
- **Freshness cap.** When the AS advertises
  `mission_max_stale_seconds` ({{as-metadata}}), it MUST NOT set
  `mission.fresh_until` later than the response `iat` plus that
  value.
- **Skew tolerance.** When comparing the current time to
  `mission.fresh_until`, a consumer MAY allow up to 30 seconds of
  tolerance for the `active` state only, and no tolerance for any
  other state. The tolerance MUST NOT exceed the AS's advertised
  `mission_max_stale_seconds` ({{as-metadata}}).

The freshness cap keeps report freshness within the deployment's
advertised revocation-propagation tolerance. The skew tolerance is a
clock-skew allowance on the reliance path, bounding the disagreement
between the AS's and the consumer's clocks, not a property of state
reversibility. The hard stop is absolute for non-`active` states
because a suspended Mission may be resumed to `active`.

## Anti-Oracle Property {#mission-status-anti-oracle}

A `mission_id` is never a bearer capability. The AS MUST authenticate
the requester and authorize it for the requested `mission_id` and
audience.

Unknown `mission_id` values and known-but-unauthorized references MUST
produce indistinguishable responses (HTTP 404 with a generic
not-found body; see {{mission-status-errors}}). The AS MUST return an
identical HTTP status code, response body, and headers for the two
cases. The AS SHOULD NOT vary response timing in a way that
distinguishes the two cases. It SHOULD mitigate timing side channels
(for example by padding response time or by taking a uniform lookup
path for both the unknown and the unauthorized case).

## Error Responses {#mission-status-errors}

Mission Status outcomes are of two kinds. A success outcome is a found,
visible, authorized Mission: the AS returns HTTP 200 with a signed
Mission Status Response, and the outcome is described by `mission.state`
in that response, not by a separate symbol. A wire error is a hard
failure: the AS returns the matching HTTP status with a JSON object
{{RFC8259}} body whose `error` member carries the symbol below.

Success outcomes (HTTP 200, signed Mission Status Response, described by
`mission.state`):

| `mission.state` | Description |
|---|---|
| `active` | Mission is active and permits reliance. |
| `suspended` | Mission is suspended (non-terminal). |
| `revoked`, `expired`, `completed`, `superseded`, `cascaded` | Mission is in a terminal, non-active state. |

This document uses "terminated" in prose for any terminal
non-`active` state; it is not itself a `mission.state` value, and the
terminal set is not closed. The terminal row above and the list that
follows enumerate the companion-defined states this suite currently
runs, for the reader's reference; a deployment reports whichever it
runs, and a consumer's reliance decision never depends on recognizing
them. The terminal states currently defined across this suite are
`revoked` and `expired` ({{I-D.draft-mcguinness-oauth-mission}}),
`completed` (this document), `superseded`
({{I-D.draft-mcguinness-oauth-mission-expansion}}), and `cascaded`
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}). The binding
rule is the issuance profile's forward-compatibility rule: every value
other than `active` is non-active, whether or not the consumer
recognizes it.

Wire error codes (carried in the `error` member of a JSON body):

| `error` | HTTP | Description |
|---|---|---|
| `invalid_request` | 400 | Malformed request: an unparseable body, a required member missing or malformed, an invalid member combination, or a retransmitted `nonce` paired with a request that is not byte-identical to the original ({{idempotency}}). |
| `unauthorized` | 401 | Request not authenticated. |
| `not_found` | 404 | Reference does not exist OR is not visible. |
| `conflict` | 409 | Lifecycle operation not legal from the current state ({{idempotency}}). |
| `stale_version` | 409 | `expected_version` differs from the current state version ({{idempotency}}). |
| `rate_limited` | 429 | Consumer is rate-limited. |
| `unavailable` | 503 | AS temporarily cannot serve status. |

Note the distinction between the two access failures: `unauthorized`
(401) means the request carried no valid authentication, whereas a
request that is authenticated but not authorized for the referenced
Mission returns `not_found` (404), never 401, so that an unauthorized
reference is indistinguishable from an unknown one
({{mission-status-anti-oracle}}). The error body is:

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

The body MUST contain `error` and `error_description`, and MUST
additionally contain `nonce` when the request carried a well-formed
`nonce`. A request whose `nonce` is absent or malformed is refused
`invalid_request` with no `nonce` member echoed. The body MUST NOT
contain any member that would let a caller distinguish unknown from
unauthorized references. For `rate_limited`, the response SHOULD
include a `Retry-After` header {{RFC9110}} and a `retry_after` body
member in seconds.

The OAuth-shaped surfaces of this family, this Status and Lifecycle
endpoint, Mission Management
{{I-D.draft-mcguinness-oauth-mission-management}}, and the Mission
Authority Server's submission surface
{{I-D.draft-mcguinness-mission-authority-server}}, share the
`error`/`error_description` JSON body idiom for consistency with the
OAuth-shaped APIs they compose with. Each surface's exact member
requiredness is its own: here and in Mission Management,
`error_description` and `nonce` are REQUIRED; the Mission Authority
Server makes `error_description` OPTIONAL and adds the MAS-only
`error_reason`.

The body is `application/json` with `Cache-Control:
no-store`. `error_description` is diagnostic and is never
authorization input. `nonce` correlates the response to the request in
support of the signed-response and retry model of {{idempotency}} and
is not, by itself, replay protection, per the absent-or-malformed-`nonce`
rule above. RFC 9457 {{RFC9457}} problem details
is neither used on these surfaces nor disparaged: the AuthZEN binding
{{I-D.draft-mcguinness-mission-authzen}} carries it where that
ecosystem does, and a future non-OAuth-shaped HTTP API in this family
MAY choose it.

# Token Introspection Mission Projection {#introspection-projection}

This section is OPTIONAL and is a thin delta over the OAuth 2.0 Token
Introspection {{RFC7662}} projection of
{{I-D.draft-mcguinness-oauth-mission}} (Section "Mission State via
Token Introspection"). That section already
defines a `mission` member on the introspection response carrying
`id` and `issuer`, and (from the Mission's issuer) the lifecycle
`state`, with `authority_hash` disclosed only to a caller holding
that member's disclosure privilege, together with the
caller-authorization, minimization, and issuer-only-reports-state
rules. This document does not restate those rules.

This extension adds the following to that projection:

- An introspection response that carries a Mission projection is
  protected by TLS, as for token introspection generally
  ({{I-D.draft-mcguinness-oauth-mission}}, Section "Mission State via
  Token Introspection"). Where the projection's integrity and provenance
  need to be verifiable independently of the transport (for example
  when the response transits intermediaries or is retained for audit),
  the AS SHOULD return it as a {{RFC9701}}-signed response, advertised
  through the `introspection_signing_alg_values_supported` metadata
  that {{RFC9701}} registers in the {{RFC8414}} registry.
- When the responding AS is the Mission's issuer, the projection MAY
  additionally carry `fresh_until`, an RFC 3339 {{RFC3339}} date-time
  giving the point until which the consumer MAY rely on the reported
  `state` without re-checking, governed by the caching rule of
  {{mission-status-caching}}. When `fresh_until` is absent (for example
  a non-issuer projection), the consumer MUST NOT cache the reported
  `state` across requests and re-checks per use or relies on the
  token's own lifetime.

This projection and the dedicated Mission Status Response
({{mission-status-response}}) carry Mission facts in a `mission` object
of the same shape: the open `mission` claim object of
{{I-D.draft-mcguinness-oauth-mission}} (Section "The Mission Claim")
with status members (`state`, `fresh_until`, any companion-defined
extension member such as the Status List companion's `status_list`
reference ({{I-D.draft-mcguinness-oauth-mission-status-list}}), and,
on the dedicated response, `expires_at` and `version`) added. This
projection populates the subset a token-holding consumer needs; the
dedicated response populates more. Either way a consumer reads the
same fact from the same place.

Example {{RFC9701}}-signed introspection response (decoded payload),
for a token whose Mission is `active`:

~~~ json
{
  "iss": "https://as.example.com",
  "aud": "https://erp.example.com",
  "iat": 1793606400,
  "token_introspection": {
    "active":  true,
    "client_id": "s6BhdRkqt3",
    "sub":     "user_3p2q8mN1a0kV7tR",
    "scope":   "invoices.read",
    "mission": {
      "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
      "issuer": "https://as.example.com",
      "authority_hash":
        "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ",
      "state":   "active",
      "fresh_until": "2026-11-02T08:00:45Z"
    }
  }
}
~~~

Per {{RFC9701}}, the signed response is a JWT of `typ`
`token-introspection+jwt` whose {{RFC7662}} members, including the
`mission` projection, ride in the `token_introspection` claim; only
`iss`, `aud`, and `iat` are top-level.

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
non-deriving, exactly as the issuance profile gates on `active`.

A transition to `suspended` or `completed` gates new derivation only.
Tokens already derived under the Mission remain valid until their own
`exp`, exactly as in the issuance profile's revocation model and
mirroring the treatment of `superseded`
({{I-D.draft-mcguinness-oauth-mission-expansion}}). A deployment that
needs a prompt cutoff on outstanding tokens uses the propagation
mechanisms of {{revocation-enforcement-classes}}.

## Operations

The endpoint accepts authenticated POST requests with a
form-urlencoded body:

`mission_id`:
: REQUIRED. A string. The canonical Mission Identifier, named per the
  issuance profile's external-surface convention
  ({{I-D.draft-mcguinness-oauth-mission}}).

`operation`:
: REQUIRED. A string. One of `revoke`, `suspend`, `resume`,
  `complete`, or a further value a companion profile registers as an
  extension operation on this endpoint, such as the Entry Discharge
  companion's `discharge`
  ({{I-D.draft-mcguinness-oauth-mission-discharge}}).

`reason`:
: OPTIONAL. A string. A human-readable reason recorded in
  audit, maximum 1024 characters. Not used by a companion-registered
  operation that records its own request members in audit, such as
  `discharge` ({{I-D.draft-mcguinness-oauth-mission-discharge}}).

`suspend_until`:
: OPTIONAL. An RFC 3339 {{RFC3339}} date-time. Valid only on the
  `suspend` operation. When present, it sets a deadline after which the
  AS applies `on_expiry`.

`on_expiry`:
: CONDITIONAL. A string, one of `resume` or `revoke`. REQUIRED when
  `suspend_until` is present; otherwise MUST NOT be sent. It selects the
  transition the AS applies when `suspend_until` passes.

`nonce`:
: REQUIRED. A string. A client-generated nonce.

A companion-registered extension operation, such as `discharge`,
carries additional REQUIRED and OPTIONAL members of its own, defined
completely by the companion that registers it
({{I-D.draft-mcguinness-oauth-mission-discharge}}).

The base operations are:

- `revoke`: terminate the Mission; transition to `revoked`.
- `suspend`: pause the Mission; transition to `suspended`.
- `resume`: return a suspended Mission to `active`.
- `complete`: mark the Mission completed; transition to `completed`.

A companion profile MAY register a further `operation` value on this
endpoint that changes no Mission-level state, provided it defines the
value's request members, authorization, anti-oracle behavior, and
result shape completely. The Entry Discharge companion registers
`discharge` this way: it commits that a completion condition has
fired, discharging a Mission-record entry, and is defined in full by
that companion ({{I-D.draft-mcguinness-oauth-mission-discharge}}).

A `suspend` MAY carry `suspend_until` with a REQUIRED `on_expiry`. When
`suspend_until` passes, the AS MUST apply `on_expiry` (transition to
`active` for `resume`, or to `revoked` for `revoke`) and emit the
corresponding transition, without a further request. While the Mission
is `suspended` under a deadline, both `suspend_until` and `on_expiry`
surface in the signed Mission Status Response ({{mission-status-response}})
so a consumer sees the pending outcome.

## Legal Transitions {#legal-transitions}

An operation is legal only from the source states below. A terminal
state (`revoked`, `expired`, `completed`, or the companion-defined
`superseded` and `cascaded`) admits no transition. An operation whose
resulting state equals the current state, terminal or not, is
idempotent success ({{idempotency}}). This table governs Mission-level
state; a companion-registered extension operation such as `discharge`
produces no Mission-state transition and is not a row of it,
following instead the entry-grain rules the Entry Discharge companion
defines ({{I-D.draft-mcguinness-oauth-mission-discharge}}).

`resume` is the sole exception: it is legal only from `suspended`
(its resulting state, `active`, is also the baseline a Mission holds
before any suspension), so `resume` on an `active` or terminal
Mission is a conflict, not idempotent success.

| Operation | Legal from | Resulting state |
|---|---|---|
| `revoke` | `active`, `suspended` | `revoked` |
| `suspend` | `active` | `suspended` |
| `resume` | `suspended` | `active` |
| `complete` | `active`, `suspended` | `completed` |

`complete` is legal from `suspended` as well as `active`: completion is
a monotonic narrowing to a terminal state and needs no derivation
window, so a suspended Mission need not first be resumed to be
completed.

Requests are adjudicated by the single rule of {{idempotency}}: an
operation whose resulting state equals the Mission's current state is
idempotent success, with the `resume` exception above. Any other
operation not legal from the current state, including `resume` on a
Mission that is not `suspended`, is refused as a conflict. A Mission
that reaches its `expires_at` transitions to `expired` independently of
this endpoint, from `active` or `suspended`.

## Consolidated State Machine {#state-machine}

This profile owns the extension of the issuance profile's lifecycle
state space ({{I-D.draft-mcguinness-oauth-mission}}, Section "Mission
Lifecycle and Gating"). The table below is the authoritative view of
that space: every state, every transition, and the source of the event
that drives it.

Event sources are the lifecycle endpoint (an operation
of {{mission-lifecycle-endpoint}}), the expiry clock (a deadline
reached without a request), and companion adjudication (a transition a
companion profile commits). The lifecycle-endpoint rows are exactly the
Mission-state-changing operations of {{legal-transitions}}; a
companion-registered extension operation such as `discharge`
({{I-D.draft-mcguinness-oauth-mission-discharge}}) is a
lifecycle-endpoint operation that changes no Mission state and so is
not a row of this table. Only `active` permits derivation; every
other state is non-deriving.

| From | Event | Event source | To |
|---|---|---|---|
| (none) | approval event | issuance profile | `active` |
| `active` | `revoke` | lifecycle endpoint | `revoked` |
| `suspended` | `revoke` | lifecycle endpoint | `revoked` |
| `active` | `suspend` | lifecycle endpoint | `suspended` |
| `suspended` | `resume` | lifecycle endpoint | `active` |
| `active` | `complete` | lifecycle endpoint | `completed` |
| `suspended` | `complete` | lifecycle endpoint | `completed` |
| `active` | `expires_at` reached | expiry clock | `expired` |
| `suspended` | `expires_at` reached | expiry clock | `expired` |
| `suspended` | `suspend_until` reached, `on_expiry` = `resume` | expiry clock | `active` |
| `suspended` | `suspend_until` reached, `on_expiry` = `revoke` | expiry clock | `revoked` |
| `active` | successor activates | expansion profile | `superseded` |
| `active` | parent reaches a terminal state | child-delegation profile | `cascaded` |
| `suspended` | parent reaches a terminal state | child-delegation profile | `cascaded` |

`revoke` and the Mission's `expires_at` both apply in `suspended` as
well as `active`, so a suspended Mission can still be terminated or
expire. The `superseded` and `cascaded` rows are companion-defined and
shown here for reference:
`superseded` is committed by the expansion profile and requires an
`active` predecessor
({{I-D.draft-mcguinness-oauth-mission-expansion}}); `cascaded` is
committed by the child-delegation profile only when a parent reaches a
terminal state. A `suspended` parent holds a dependent Child Mission
non-active reversibly rather than driving it to `cascaded`
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}). Neither
companion state is produced by this profile's endpoint.

## Authentication

The lifecycle endpoint uses the same authentication mechanisms as the
Mission Status endpoint ({{mission-status-authentication}}): mTLS client
authentication, a sender-constrained access token (DPoP- or mTLS-bound),
or private-key JWT. Its discovery mirrors that endpoint: the accepted
methods in `mission_lifecycle_endpoint_auth_methods_supported` and, for
`private_key_jwt`, the accepted client-assertion algorithms in
`mission_lifecycle_endpoint_auth_signing_alg_values_supported`
({{as-metadata}}).

For the sender-constrained access-token path, this
endpoint is an OAuth protected resource exactly as the Mission Status
endpoint is: the AS publishes, in its Protected Resource Metadata for
this resource {{RFC9728}}, the `resource` identifier the token's
audience MUST name and the scopes it requires (`scopes_supported`):
`mission_lifecycle` for `revoke`, `suspend`, `resume`, and `complete`
({{mission-lifecycle-endpoint}}), and, where the deployment adopts the
Entry Discharge companion, `mission_discharge` as well
({{I-D.draft-mcguinness-oauth-mission-discharge}}). A private-key JWT
`client_assertion` MUST name the `mission_lifecycle_endpoint` URL in
`aud`, and a presented access token MUST be audience-restricted to
this endpoint's protected-resource identifier, exactly as at the
Mission Status endpoint. Direct mTLS or private-key-JWT callers
continue to use the deployment-defined equivalent grant, never a
scope, exactly as a companion-registered extension operation such as
`discharge` does
({{I-D.draft-mcguinness-oauth-mission-discharge}}).

## Authorization

This section governs `revoke`, `suspend`, `resume`, and `complete`; a
companion-registered extension operation such as `discharge` has its
own distinct authority model
({{I-D.draft-mcguinness-oauth-mission-discharge}}), which a
`mission_lifecycle` grant under this section MUST NOT imply.

The AS authorizes lifecycle operations against deployment policy. This
document sets the minimum authorization semantics and leaves finer
policy deployment-defined. Every authenticated caller, whatever its
authentication mechanism ({{mission-status-authentication}}), MUST be
governed by an explicit lifecycle authorization: a `mission_lifecycle`
scope or a deployment-defined equivalent grant that names who may
perform the transition. The AS MUST refuse a caller that carries no
such authorization.

The acting party, and where the AS checks the lifecycle
authorization, follow from the authentication case:

1. When an access token authenticates the call, the token identifies
   the parties per the issuance profile's access-token model
   ({{I-D.draft-mcguinness-oauth-mission}}): for a delegated access
   token its `sub` denotes the resource owner (the represented party),
   matching the {{RFC9068}} access-token `sub` model; the calling party
   is identified by `client_id` ({{RFC8693}} Section 4.3); and, where a
   delegation chain is present, the immediate actor is identified by the
   `act` claim ({{RFC8693}}, {{I-D.draft-mcguinness-oauth-mission}}). A
   DPoP {{RFC9449}} or mTLS
   {{RFC8705}} sender constraint binds the presenter to a key; it does
   not change what `sub` denotes. The acting party is the calling party
   so identified, and the presented token MUST carry the lifecycle
   authorization the AS checks against it.
2. When the caller authenticates directly as a client (mTLS client
   authentication {{RFC8705}} or private-key JWT {{RFC7523}}), the
   authenticated client is the acting party. The AS MUST check the
   deployment-defined lifecycle grant bound to that client.

In every case the AS MUST record the acting party and SHOULD reflect
it in the signed response's audit surface: the response envelope's
`sub`, distinct from any access token's `sub`, or a deployment-defined
audit member of the Mission Status Response.

Which parties may perform which operation is deployment-defined. Typical
deployments authorize `revoke` to the Mission's Subject or Approver and
to administrators; `suspend` and `resume` to administrators; and
`complete` to the requesting client or an administrator.

Because `resume` returns a suspended Mission to `active` and so undoes
the containment a `suspend` established, a deployment SHOULD require a
distinct or elevated authorization for `resume`, mirroring the
treatment of bulk `resume` in Mission Management
({{I-D.draft-mcguinness-oauth-mission-management}}).

The AS MUST refuse an unauthorized lifecycle request with the
not-found response shape of {{mission-status-errors}}, so the endpoint
does not act as a Mission enumeration oracle.

## Worked Examples

Revoke request:

~~~ http-message
POST /as/mission/lifecycle HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: DPoP eyJhbGciOiJFUzI1NiIsImtpZCI6...
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2Iiwi...

mission_id=msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-
&operation=revoke
&reason=Quarterly+reconcile+completed+early
&nonce=nonce_8Y3vN0sM6tP1xR9bQ5
~~~

Revoke success response: the AS returns the updated status as a signed
Mission Status Response ({{mission-status-response}}). Because the
Lifecycle request carries no `audience`, the response is state-only: the
AS sets `aud` to the authenticated requester and omits
`authorization_details` (a lifecycle confirmation reports `state`, not
audience-scoped authority). Here the response envelope's `sub`,
distinct from any access token's `sub`, carries the acting party: the
calling client identified by `client_id`. The AS records that acting
party and reflects it in this signed response as well as in its audit
log.

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
  "aud": "client_erp-recon-agent",
  "sub": "client_erp-recon-agent",
  "nonce": "nonce_8Y3vN0sM6tP1xR9bQ5",
  "iat": 1793609600,
  "exp": 1793609660,
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "issuer": "https://as.example.com",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ",
    "state": "revoked",
    "version": 7,
    "expires_at":  "2026-12-31T23:59:59Z",
    "fresh_until": "2026-11-02T08:54:05Z"
  }
}
~~~

The AS records the operation, actor, time, and any `reason` in its
audit log; the response confirms the outcome through the updated
`state`.

Suspend request with a deadline, here also carrying the OPTIONAL
`expected_version` guard against deciding over stale state
({{idempotency}}):

~~~ http-message
POST /as/mission/lifecycle HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: DPoP eyJhbGciOiJFUzI1NiIsImtpZCI6...
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2Iiwi...

mission_id=msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-
&operation=suspend
&suspend_until=2026-11-09T08%3A15%3A00Z
&on_expiry=revoke
&expected_version=5
&reason=Pending+quarterly+access+review
&nonce=nonce_4Dq2mV8kX1sB7nR3tW
~~~

Suspend success response: the signed Mission Status Response reports
`suspended` and surfaces the pending outcome, carrying `suspend_until`
and `on_expiry` in `mission` alongside `state`. Decoded JWS payload:

~~~ json
{
  "iss": "https://as.example.com",
  "aud": "client_erp-recon-agent",
  "sub": "client_erp-recon-agent",
  "nonce": "nonce_4Dq2mV8kX1sB7nR3tW",
  "iat": 1793607600,
  "exp": 1793607660,
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "issuer": "https://as.example.com",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ",
    "state": "suspended",
    "version": 6,
    "suspend_until": "2026-11-09T08:15:00Z",
    "on_expiry": "revoke",
    "expires_at":  "2026-12-31T23:59:59Z",
    "fresh_until": "2026-11-02T08:20:45Z"
  }
}
~~~

When `suspend_until` passes without a `resume`, the AS applies
`on_expiry` and transitions the Mission to `revoked` without a further
request.

## Idempotency and Conflicts {#idempotency}

The request `nonce` ({{mission-lifecycle-endpoint}}, Operations) is
the idempotency key: an opaque string of 1 to 255 characters. The AS
treats an absent, empty, longer, or non-string `nonce` as malformed
(`invalid_request`, with no `nonce` echoed).

The AS MUST deduplicate
lifecycle requests by the
triple (client, `mission_id`, `nonce`) for a bounded window. On a
retransmit carrying a `nonce` already seen for that client and
`mission_id`, together with a request byte-identical to the original,
the AS MUST replay the original response rather than re-execute the
operation. The same `nonce` paired with a request that is not
byte-identical to the original MUST be refused `invalid_request`
({{mission-status-errors}}); the AS MUST NOT answer it with the
unrelated original response.

The window MUST be at least the validity
span of the signed response the AS would replay (its `iat` to `exp`,
{{mission-status-response}}), so any retransmit that could still
present a live response is deduplicated. A deployment MAY use a longer
window. This makes a retransmit safe against reordering: a
delayed `suspend` retry that arrives after a `resume` is recognized as
a duplicate and replays the original `suspend` response, so it cannot
re-suspend an already-resumed Mission.

Deduplication guards a retransmitted request; it does not guard a
valid request decided over stale state, a fresh `suspend` issued from
a console that has not yet seen a newer `resume`. For that a
lifecycle request MAY carry `expected_version`, the state version
({{mission-status-response}}) the caller last observed: when present,
the AS MUST refuse the operation with HTTP 409 and error symbol
`stale_version`, leaving the Mission unchanged, when the Mission's
current state version differs. A deployment SHOULD require
`expected_version` on the operations it classifies high-risk. The
`nonce` remains the replay key; the two guards are independent, one
against duplicate delivery, one against stale decisions.

Lifecycle operations that change Mission state follow one rule. An
operation whose resulting state ({{legal-transitions}}) equals the
Mission's current state is idempotent success, terminal or not: the AS
returns the current Mission Status Response, with no state change and
no event emitted. Any other operation not legal from the current state
(for example `suspend` against a terminal state) is a conflict: the AS
MUST refuse it with HTTP 409 and a JSON body whose error symbol is
`conflict`, leaving the Mission state unchanged. A companion-registered
extension operation that changes no Mission state, such as `discharge`,
is not bound by this rule; its own idempotency and outcome vocabulary
are defined by the companion that registers it, for `discharge` by the
Entry Discharge companion
({{I-D.draft-mcguinness-oauth-mission-discharge}}).

`resume` is the sole exception to the idempotent-success arm. It is
legal only from `suspended`, and its resulting state `active` is also
the baseline a Mission holds before any suspension, so `resume` on an
`active` Mission (one never suspended, or already resumed) or on a
terminal Mission is not idempotent success but a conflict.

One idempotent case carries metadata. A `suspend` against a
`suspended` Mission whose `suspend_until` or `on_expiry` differ from
the recorded values MUST update the recorded values, emitting the
corresponding transition-metadata change and reporting the updated
values in the response; silent acceptance without effect is not
conforming.

## Relationship to RFC 7009

A Mission revocation through this endpoint cascades to credentials
derived from the Mission per the AS's advertised revocation
propagation ({{revocation-enforcement-classes}}). The AS MAY additionally invoke
{{RFC7009}} token revocation for specific outstanding tokens when it
knows their `jti`. {{RFC7009}} alone does NOT revoke a Mission; the
lifecycle endpoint is the authoritative Mission state change.

## Deferred Lifecycle Capabilities {#deferred-lifecycle}

This endpoint operates on one Mission at a time. Mission enumeration
and bulk lifecycle operations for incident response, such as revoking
every Mission for a compromised Subject, client, or tenant, are
specified separately by Mission Management
{{I-D.draft-mcguinness-oauth-mission-management}}; this document does
not require them.

The following capabilities remain deferred to future
work:

- Approver transfer or re-anchoring, changing the party that
  anchors a Mission's consent, is not defined here.
- Administrative
  monotonic narrowing, such as shortening a Mission's `expires_at`, is
  not defined here.

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
mechanisms to match. When the member is absent, no propagation bound
is declared: a consumer MUST size reliance to token lifetime alone
and MUST NOT assume a tighter bound.

Where the member is present, a status response's `mission.fresh_until`
MUST NOT exceed the response's issuance time plus the advertised
bound: the advertisement is the ceiling on every reliance window
built from these surfaces, including a runtime permit's validity
window, which is capped by the state view's freshness. As sizing
guidance, the runtime enforcement profile's recommended defaults
target an effective bound under 300 seconds for the high-consequence
classes; the 60-second value in this document's examples is a tight
deployment's choice, not a floor.

## Recommended Access-Token TTL

Where Mission revocation must take effect but only the baseline
derivation-time check is in use, Mission-bound access tokens SHOULD use
TTLs no longer than the declared `mission_max_stale_seconds`.
Deployments where revocation propagates out of band (token
introspection, per-request status checks, or the event stream) MAY use
longer TTLs.

Sizing to the bound is itself a propagation mechanism: expiry
performs the state check, and the consumer integrates nothing (the
runtime profile names this token-lifetime freshness for the classes
below its high-consequence floor). Introspection and per-request
status checks tighten specific paths; they are upgrades, not
prerequisites.

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

`mission_status_endpoint_auth_methods_supported`:
: OPTIONAL. A JSON array of strings naming the authentication methods
  the Mission Status endpoint ({{mission-status}}) accepts. Its value
  space is a closed set defined by this document, not the OAuth Token
  Endpoint Authentication Methods registry: `mtls_client_auth`
  (mutual-TLS client authentication {{RFC8705}}), `private_key_jwt`
  (private-key JWT client authentication {{RFC7523}}), and `access_token`
  (a `mission_status`-scoped, sender-constrained access token, whose
  presentation and DPoP or mTLS binding are described by this endpoint's
  Protected Resource Metadata {{RFC9728}}). The first two values are
  spelled identically to registered token-endpoint authentication
  methods by intent; this member describes this endpoint, not the token
  endpoint. Present, and SHOULD be advertised, when the AS serves the
  Mission Status endpoint.

`mission_status_endpoint_auth_signing_alg_values_supported`:
: OPTIONAL. A JSON array of strings, the JWS {{RFC7515}} algorithm
  values the AS accepts for the `private_key_jwt` client-assertion JWT
  ({{mission-status-authentication}}) at the Mission Status endpoint.
  This is the client-assertion verification set, not the response-signing
  algorithms of `mission_status_signing_alg_values_supported` below.
  `none` MUST NOT be used. Present when that endpoint lists
  `private_key_jwt`.

`mission_status_signing_alg_values_supported`:
: OPTIONAL. A JSON array of strings. The JWS {{RFC7515}} algorithm
  values the AS uses to sign the Mission Status Response shape
  ({{mission-status-response}}), on whichever surfaces of this
  profile family serve it (the dedicated Mission Status operation,
  the Lifecycle endpoint, and Mission Management), mirroring
  `introspection_signing_alg_values_supported`. These are the
  response-signing algorithms, not the algorithms the AS accepts on
  `private_key_jwt` client assertions (the endpoint auth-signing
  members). Present when the AS serves any such surface.

`mission_lifecycle_endpoint`:
: OPTIONAL. A string containing a URL. The URL of the
  Mission Lifecycle endpoint ({{mission-lifecycle-endpoint}}). Present
  when the AS supports it.

`mission_lifecycle_endpoint_auth_methods_supported`:
: OPTIONAL. A JSON array of strings naming the authentication methods
  the Mission Lifecycle endpoint ({{mission-lifecycle-endpoint}})
  accepts, from the same closed value space as
  `mission_status_endpoint_auth_methods_supported` (with `access_token`
  naming a `mission_lifecycle`-scoped access token). Present, and SHOULD
  be advertised, when the AS serves the Mission Lifecycle endpoint.

`mission_lifecycle_endpoint_auth_signing_alg_values_supported`:
: OPTIONAL. A JSON array of strings, the JWS {{RFC7515}} algorithm
  values the AS accepts for the `private_key_jwt` client-assertion JWT
  ({{mission-status-authentication}}) at the Mission Lifecycle endpoint.
  This is the client-assertion verification set, not the response-signing
  algorithms of `mission_status_signing_alg_values_supported`.
  `none` MUST NOT be used. Present when that endpoint lists
  `private_key_jwt`.

`mission_max_stale_seconds`:
: OPTIONAL. An integer. The maximum
  tolerated interval, in seconds, for revocation propagation
  ({{revocation-enforcement-classes}}). When absent, no bound is
  declared, and a consumer sizes reliance to token lifetime alone.

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
  "mission_status_endpoint_auth_methods_supported":
    ["mtls_client_auth", "private_key_jwt", "access_token"],
  "mission_status_endpoint_auth_signing_alg_values_supported": ["ES256"],
  "mission_status_signing_alg_values_supported": ["ES256"],
  "mission_lifecycle_endpoint":
    "https://as.example.com/as/mission/lifecycle",
  "mission_lifecycle_endpoint_auth_methods_supported":
    ["mtls_client_auth", "private_key_jwt", "access_token"],
  "mission_lifecycle_endpoint_auth_signing_alg_values_supported": ["ES256"],
  "mission_max_stale_seconds": 60
}
~~~

# Conformance {#conformance}

An implementation conforms to the issuance profile
{{I-D.draft-mcguinness-oauth-mission}} or implements the Mission
Issuer role of a binding that serves these surfaces, such as the
standalone Mission Authority Server
{{I-D.draft-mcguinness-mission-authority-server}}. Each extension in this
document is independently OPTIONAL; an implementation names the ones it
supports (for example, "issuance profile with Mission Status and
Mission Lifecycle"), and an implementation that supports none of them
is still a conforming issuance profile.

An implementation claiming an extension MUST meet its requirements:

- **Mission Status**: serve the dedicated Mission Status operation
  ({{mission-status}}) with JWS-signed responses
  (`application/mission-status-response+jwt`), the authentication and
  read authorization of {{mission-status-authentication}}, the
  anti-oracle property
  ({{mission-status-anti-oracle}}), and the error shape of
  {{mission-status-errors}}; and advertise `mission_status_endpoint` and
  `mission_status_endpoint_auth_methods_supported`.
- **Introspection projection**: carry the Mission projection on the
  introspection response ({{introspection-projection}}), returning it
  as a {{RFC9701}}-signed response where end-to-end integrity is
  required.
- **Mission Lifecycle**: serve the management endpoint
  ({{mission-lifecycle-endpoint}}), gate the `suspended` and
  `completed` states it introduces exactly as the issuance profile gates
  on non-`active` state, and advertise `mission_lifecycle_endpoint` and
  `mission_lifecycle_endpoint_auth_methods_supported`.
- **Revocation propagation**: advertise `mission_max_stale_seconds`
  and size Mission-bound access-token TTLs to it
  ({{revocation-enforcement-classes}}).

A companion profile MAY register a further extension operation on the
Mission Lifecycle endpoint and carry its own conformance requirements;
the Entry Discharge companion's `terminal_when` and `discharge`
capability is conformant to its own document, not to this one
({{I-D.draft-mcguinness-oauth-mission-discharge}}).

An implementation meets the following requirement independent of
which extensions above it claims, and independent of which companion
profiles it adopts. Every issuer-held narrowing mechanism a
deployment runs, an adopted companion's discharge mechanism or
another companion profile's own overlay alike, MUST feed the single
Effective Authority Set computation. Every derivation and every
authority-reporting surface MUST use that same computation; no
mechanism computes a parallel view, and no surface reports authority
the computation has not reduced.

# Security Considerations {#security-considerations}

The security considerations of the issuance profile
{{I-D.draft-mcguinness-oauth-mission}} apply in full. This section
covers threats specific to the extensions defined here.

## Mission Status Enumeration

Per the anti-oracle property ({{mission-status-anti-oracle}}), the AS
MUST NOT let a caller readily distinguish an unknown `mission_id` from a
known-but-unauthorized one at the Status or Lifecycle endpoint. The
error shape of {{mission-status-errors}} requires identical body
content, identical HTTP status, and identical headers between the two
cases, and the AS SHOULD additionally suppress timing side channels
(for example by padding response time or by taking a uniform lookup
path). An implementation that leaks the distinction exposes the Mission
space to enumeration.

## Mission Status Response Replay

A Mission Status Response is bound to (caller `sub`, audience,
`nonce`, issuance time). Replay against a different caller or audience,
or beyond `mission.fresh_until`, is detectable by signature
verification and by verifying the bindings; a consumer MUST verify all
the checks of {{mission-status-response}} before honoring a response. A
response cached and replayed by the same caller within
`mission.fresh_until` is equivalent to a fresh response; a consumer MUST
NOT use a cached response after `mission.fresh_until`, with the skew
tolerance of {{mission-status-caching}}.

## Mission Status Denial of Service

The Mission Status operation is on the consumption path of every
Mission-bound credential validation in deployments where consumers query
Mission Status per request.
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
dedicated Mission Status operation, and MUST NOT accept an unsigned
response from the dedicated Mission Status operation in place of the
signed form it requires.

## Signing-Key Retention for Audit

The AS signs Mission Status and Lifecycle responses with a key from
its `jwks_uri`. The AS MUST keep the public JWK for every `kid` it
has signed such a response under resolvable in its `jwks_uri` for at
least the Mission record retention period, so an archived
`application/mission-status-response+jwt` remains verifiable for
audit and dispute. This is the issuance profile's retired-key rule
({{I-D.draft-mcguinness-oauth-mission}}), with the record retention
period as the bound. A key known or suspected
compromised is the exception: the AS removes it, and the Mandate
profile's compromise-time rule governs how artifacts signed under it
are then classified.

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
Mission state and the audience-scoped `authorization_details` to the
authenticated, authorized requester, and MAY additionally disclose
`authority_hash` to a requester authorized for it. A deployment MUST
treat both as Mission information-disclosure surfaces with the same
privacy posture, audience-filtering the disclosed authority so a
consumer never sees entries addressed to other audiences
({{mission-status-response}}).

## Status Audit Logging

The AS records Status and Lifecycle requests (containing
`mission_id`, audience, caller, and timing) in audit logs.
Deployments MUST treat these logs as PII sinks per the issuance
profile's privacy considerations.

# IANA Considerations {#iana}

This document requests IANA actions for OAuth AS metadata members and
a media type. It defines no new registry of its own: the endpoint
authentication-method value space is a closed set defined inline
({{as-metadata}}). A companion profile MAY register further extension
members or Common Constraints against a family registry; the Entry
Discharge companion registers `terminal_when` in the Mission Resource
Access Profile's Mission Common Constraints registry this way
({{I-D.draft-mcguinness-oauth-mission-discharge}}).

## OAuth Authorization Server Metadata Registration

IANA is requested to register the following in the "OAuth
Authorization Server Metadata" registry {{RFC8414}}. For each:
Change Controller IETF; Reference this document, {{as-metadata}}.

- `mission_status_endpoint`
- `mission_status_endpoint_auth_methods_supported`
- `mission_status_endpoint_auth_signing_alg_values_supported`
- `mission_status_signing_alg_values_supported`
- `mission_lifecycle_endpoint`
- `mission_lifecycle_endpoint_auth_methods_supported`
- `mission_lifecycle_endpoint_auth_signing_alg_values_supported`
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

## Mission Lifecycle States Registrations {#iana-lifecycle-registrations}

This document requests registration of two states in the issuance
profile's Mission Lifecycle States registry
({{I-D.draft-mcguinness-oauth-mission}}), under that registry's
Specification Required policy:

| Value | Terminal | Semantics | Change Controller | Reference |
|---|---|---|---|---|
| `suspended` | no | A paused Mission that derives no tokens until resumed. | IETF | this document, {{mission-lifecycle-endpoint}} |
| `completed` | yes | Records successful completion of the Mission. | IETF | this document, {{mission-lifecycle-endpoint}} |

## Well-Known URI

This document registers no new Well-Known URI. The metadata members of
{{as-metadata}} are added to the OAuth Authorization Server Metadata
document at `/.well-known/oauth-authorization-server` {{RFC8414}}.

# Acknowledgments
{:numbered="false"}

The author thanks the implementers and reviewers of the Mission-Bound
Authorization work for feedback that shaped these extensions.

--- back

# Document History {#document-history}

\[\[ To be removed from the final specification ]]

- Added conditional carryover correlation on an old child's cascaded
  observation; no state or authority is inferred from the pointer (#576).
