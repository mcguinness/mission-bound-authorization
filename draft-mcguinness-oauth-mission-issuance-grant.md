---
title: "Mission Issuance Grant for OAuth 2.0"
abbrev: "Mission Issuance Grant"
category: std

docname: draft-mcguinness-oauth-mission-issuance-grant-latest
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
 - issuance
 - grant
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-issuance-grant.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC6749:
  RFC6838:
  RFC7515:
  RFC7519:
  RFC7523:
  RFC7800:
  RFC8414:
  RFC8705:
  RFC9126:
  RFC9396:
  RFC9449:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
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
  I-D.draft-mcguinness-oauth-mission-status:
    title: "Mission Status and Lifecycle for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-status.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

informative:
  RFC8725:
  RFC8693:
  I-D.draft-mcguinness-oauth-mission-containment:
    title: "Mission Containment for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-containment.html
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
  I-D.draft-mcguinness-oauth-mission-cross-domain:
    title: "Mission Cross-Domain Projection for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-cross-domain.html
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
  I-D.draft-mcguinness-mission-architecture:
    title: "An Architecture for Mission-Bound Authorization"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-architecture.html
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

--- abstract

The standalone Mission Authority Server binding governs Missions with
no change to an estate's Authorization Servers: tokens remain
ordinary, and enforcement joins them to Missions at the point of use.
That mode provides no Mission-bound credential and no issuance
gating. This document defines the Mission Issuance Grant: a
short-lived, audience-bound, one-time assertion, minted by a
standalone Mission Issuer for an approved, active Mission, that an
OAuth Authorization Server redeems at its token endpoint to issue
Mission-bound tokens gated on Mission state and the Mission's current
effective authority. Approval, record, and lifecycle stay at the
Mission Authority Server; the Authorization Server keeps the token
plane and adds only grant validation, subset-bounded minting, and
refresh gated on that same state and effective authority. This
issuance join restores Mission-bound credentials and the
issuance-gate kill switch
without the Authorization Server implementing the issuance profile's
intake, approval, or derivation surfaces.

--- middle

# Introduction

Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} (the "issuance profile") binds issued authority to a durable, human-approved
Mission, with the Authorization Server (AS) as the Mission Issuer.
The Mission Authority Server (MAS,
{{I-D.draft-mcguinness-mission-authority-server}}) hosts the same
object without touching the AS: it validates Mission Intents, runs
approval, records Missions, and operates the lifecycle, while tokens
remain ordinary and a Policy Decision Point joins them to Missions at
the point of use. Between those two integrations there was none: an
estate either changed its AS completely or not at all.

This document defines the middle integration, the **issuance join**.
The MAS remains the Mission Issuer; the estate's AS consumes the
approved Mission at its token endpoint. The carrier is the **Mission
Issuance Grant**, a short-lived assertion the MAS mints for an
active Mission and the AS redeems under the JWT authorization grant
{{RFC7523}} to issue tokens that carry the `mission` claim and are
bounded by the Mission's derived authority. Because every grant is
minted against current Mission state, and both redemption and refresh
are gated on that state and on the Mission's current effective
authority, the possession-independent kill switch returns to the
issuance gate, the property the MAS-only mode structurally lacks.

The Authorization Server's obligations are deliberately small:
validate the grant, mint within its bounds, gate issuance and refresh
on Mission state and current effective authority. It implements none
of the issuance profile's intake, approval ceremony,
derivation, record, or lifecycle surfaces; those stay at the MAS.
The integration ladder is then: record-only governance, the runtime
join, the issuance join, and native Mission-awareness, each adopted
where its cost is warranted
({{I-D.draft-mcguinness-mission-authority-server}}).

# Status: An Optional Profile {#doc-status}

<!-- family-status: BEGIN (generated from family-manifest.json; exact-matched by scripts/check-family-manifest.mjs) -->
Maturity: stable. Maintenance: active.
Adopt when: A MAS-governed estate wants Mission-bound gated tokens without full intake at each AS.
Requires: Mission Authority Server; Mission-Bound Authorization for OAuth 2.0.
Also requires, conditionally: Mission Status and Lifecycle for OAuth 2.0 (when Status supplies state and the Effective Authority Set).
<!-- family-status: END -->

# Conventions and Terminology {#conventions}

{::boilerplate bcp14-tagged}

This document uses Mission, Mission Intent, Authority Set, Mission
Issuer, the `mission` claim, the subset rule, and the integrity
anchors (`intent_hash`, `authority_hash`) as the issuance profile defines them,
Mission Authority Server (MAS), Mission Join, and the Enterprise
Mapping Contract as {{I-D.draft-mcguinness-mission-authority-server}}
defines them, and Effective Authority Set as
{{I-D.draft-mcguinness-oauth-mission-status}} defines it. It
additionally uses:

Issuance join:
: The integration this document defines: a MAS-approved Mission
  consumed at an Authorization Server's token endpoint.

Mission Issuance Grant (grant):
: The signed assertion of {{grant}}, minted by the Mission Issuer
  and redeemed for Mission-bound tokens.

Grant Minter:
: The standalone Mission Issuer minting grants; conformance role of
  {{conformance}}.

Consuming Authorization Server (consuming AS):
: An OAuth Authorization Server {{RFC6749}} that redeems Mission
  Issuance Grants at its token endpoint; conformance role of
  {{conformance}}.

# The Issuance Join {#issuance-join}

Trust is pre-established and bilateral. A consuming AS accepts
grants only from Mission Issuers its local policy names, resolving
their signing keys through the MAS's published key material (its
discovery `jwks_uri`,
{{I-D.draft-mcguinness-mission-authority-server}}); a MAS mints
grants only for Authorization Servers named as audiences by
deployment configuration. Subject and client correspondence between
the Mission record and the consuming AS's accounts is governed by
the deployment's mapping policy; where the Enterprise Mission
Authority Profile is claimed, its mapping contract governs
({{I-D.draft-mcguinness-mission-authority-server}}).

The division of duties is fixed. The MAS holds the approval event,
the record and its anchors, the lifecycle, and grant minting. The
consuming AS holds client authentication, token minting bounded by
the grant, refresh, and its ordinary token-plane obligations. An
auditor attributes what was approved to the MAS record and what was
issued to the consuming AS's log, joined by the Mission reference
the grant carries.

Tokens issued under this profile are Mission-bound in the issuance profile's
sense: they carry the `mission` claim, their authority is a subset
of the consented Authority Set, and issuance and refresh are gated
on Mission state. Runtime enforcement
({{I-D.draft-mcguinness-mission-runtime}}) composes
credential-carried for these tokens; the MAS-only mode's join caveat
(the credential's membership is mapped, not issued) does not apply
to them. Tokens the estate issues outside this profile are
unchanged and continue to compose through the Mission Join.

# The Mission Issuance Grant {#grant}

A Mission Issuance Grant is a JWT {{RFC7519}} signed as a JWS
{{RFC7515}} by the Mission Issuer. Its JOSE header MUST carry `typ`
`mission-issuance-grant+jwt` ({{iana}}), `alg`, and a `kid` that
resolves in the Mission Issuer's published key material. A consumer
MUST reject as a Mission Issuance Grant any JWT whose `typ` differs;
in particular a Mission Mandate
({{I-D.draft-mcguinness-mission-mandate}}) is evidence, authorizes
nothing, and MUST NOT redeem.

Claims:

`iss`:
: REQUIRED. The Mission's `issuer`: the MAS issuer URL.

`sub`:
: REQUIRED. The Mission's recorded Subject identifier
  (`subject.sub`), interpreted at the consuming AS under the
  deployment's mapping policy ({{issuance-join}}).

`aud`:
: REQUIRED. The consuming AS's issuer identifier. A consuming AS
  MUST reject a grant whose `aud` does not name it.

`iat`, `exp`:
: REQUIRED. The grant MUST NOT be valid longer than 300 seconds.

`jti`:
: REQUIRED. Unique per grant; single use ({{redemption}}).

`client_id`:
: REQUIRED. The Mission's recorded agent client identifier at the
  consuming AS. Only this authenticated client redeems the grant.

`mission`:
: REQUIRED. The issuance profile's `mission` claim object (`id`, `issuer`,
  `authority_hash`), exactly as recorded, extended with the
  `expires_at` member of {{expires-at-member}}.

`authorization_details`:
: REQUIRED. The `mission_resource_access` entries {{RFC9396}} the
  consuming AS may mint against: a subset of the Mission's consented
  Authority Set, scoped to the resources this AS serves.

`cnf`:
: OPTIONAL. A proof-of-possession key binding {{RFC7800}} for
  redemption; when present, the consuming AS MUST require proof of
  possession of the bound key at redemption, demonstrated with DPoP
  {{RFC9449}} or mutual TLS {{RFC8705}} as the deployment configures.

An illustrative decoded grant (this Mission and its anchors are not
the one from the issuance profile's walkthrough):

~~~ json
{
  "iss": "https://mas.example.com",
  "sub": "user_3p2q8mN1a0kV7tR",
  "aud": "https://as.example.com",
  "iat": 1793606400,
  "exp": 1793606580,
  "jti": "mig_7Kq2Rv9Lp4xW1nT8",
  "client_id": "s6BhdRkqt3",
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "issuer": "https://mas.example.com",
    "authority_hash":
      "sha-256:R6tY2nD9bM7sX1cF8gH2vJ4kE5pNQl3KvZ4mP5x0wQr",
    "expires_at": "2026-12-31T23:59:59Z"
  },
  "authorization_details": [
    {
      "type": "mission_resource_access",
      "resource": "https://api.example.com/invoices",
      "actions": ["read"],
      "constraints": { "resource_issued_after": "2026-07-01" }
    }
  ]
}
~~~

## The `expires_at` Claim Member {#expires-at-member}

The issuance profile defines `expires_at` as a REQUIRED Mission
Record member and an OPTIONAL member of the `mission` claim it
mirrors ({{I-D.draft-mcguinness-oauth-mission}}). This profile
elevates the claim mirror to REQUIRED for the credentials it governs:
the `mission` object ({{grant}}) is REQUIRED and extended with
`expires_at`. The Lifetime rule ({{redemption}}) depends on that
elevation: no token issued under the grant may expire later than the
`mission` object's `expires_at`.

# Obtaining a Grant {#minting}

A MAS implementing this profile serves a Mission Issuance Grant
endpoint, published as `mission_issuance_grant_endpoint` in its
discovery metadata ({{iana}}). The Grant Minter MUST observe:

1. **Requester.** The endpoint requires authentication. The
   requester MUST be the Mission's recorded client; any other caller
   receives the MAS's `not_found` anti-oracle response, under the
   same visibility rules as the Mission Join Assertion
   ({{I-D.draft-mcguinness-mission-authority-server}}).
2. **State gate.** A grant is minted only while the Mission is
   `active`, established from the MAS's own record at minting. Any
   other state refuses.
3. **Subset and audience.** The grant's `authorization_details` MUST
   be a subset of the Mission's consented Authority Set under the
   issuance profile's subset rule. The grant SHOULD carry only the entries the
   named consuming AS serves. The requester MAY request a narrower
   subset. The requester MUST NOT obtain a wider one.
4. **Derivation event.** Each grant minted is a derivation event.
   Where the Mission carries a consented `controls.max_derivations`,
   the MAS MUST count grants against it atomically and refuse beyond
   it, which gives that control a binding locus under the standalone
   binding.
5. **Evidence.** Each minting is recorded with the Mission record:
   the `jti`, audience, requested and granted entries, and time.

## Grant Request {#minting-request}

The requester POSTs an `application/json` object to the endpoint over
TLS, authenticated as {{minting}} requires:

`mission_id`:
: REQUIRED. A string. The Mission the grant is minted for; its
  `issuer` is this MAS.

`audience`:
: REQUIRED. A string. The consuming AS the grant is for, becoming the
  grant's `aud`. The MAS mints only for audiences its configuration
  names ({{issuance-join}}).

`authorization_details`:
: OPTIONAL. An array. A narrower subset the requester asks the grant to
  carry, under the issuance profile's subset rule. Omitted, the MAS scopes the
  grant to the entries the named audience serves ({{minting}}); present,
  it MUST NOT widen beyond that scope.

On success the endpoint returns HTTP 200 with an `application/json`
object:

`grant`:
: REQUIRED. A string. The Mission Issuance Grant JWT of {{grant}}. Its
  `exp` bounds redemption ({{grant}}); the requester reads the deadline
  from the decoded grant.

~~~ http-message
POST /mas/mission/issuance-grant HTTP/1.1
Host: mas.example.com
Content-Type: application/json
Authorization: DPoP eyJhbGciOiJFUzI1NiIsImtpZCI6...
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2Iiwi...

{
  "mission_id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
  "audience": "https://as.example.com",
  "authorization_details": [
    {
      "type": "mission_resource_access",
      "resource": "https://api.example.com/invoices",
      "actions": ["read"]
    }
  ]
}
~~~

~~~ http-message
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "grant": "eyJ0eXAiOiJtaXNzaW9uLWlzc3VhbmNlLWdyYW50K2p3dCIs..."
}
~~~

## Grant Errors {#minting-errors}

A failure returns the MAS error object
({{I-D.draft-mcguinness-mission-authority-server}}): a JSON body with a
REQUIRED `error` string and an OPTIONAL `error_description`. This
endpoint uses:

| `error` | HTTP | Condition |
|---|---|---|
| `invalid_request` | 400 | Missing or malformed `mission_id` or `audience`, or an unparseable body. |
| `unauthorized` | 401 | Request not authenticated. |
| `not_found` | 404 | The `mission_id` is unknown, or the requester is not the Mission's recorded client. |
| `invalid_audience` | 400 | `audience` names no AS this MAS mints for. |
| `mission_not_active` | 409 | The Mission is not `active` ({{minting}}). |
| `invalid_authorization_details` | 400 | The requested subset is not a subset of the consented Authority Set, or exceeds the audience scope. |
| `max_derivations_exhausted` | 409 | A consented `controls.max_derivations` is reached ({{minting}}). |

`not_found` covers both an unknown Mission and a requester that is not
the recorded client, so the split never becomes a membership oracle;
the other codes are returned only to the authenticated recorded client,
to which Mission state is already visible.

# Redemption {#redemption}

The client presents the grant to the consuming AS's token endpoint
as a JWT authorization grant {{RFC7523}}:

~~~
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer
&assertion=eyJ0eXAiOiJtaXNzaW9uLWlzc3VhbmNlLWdyYW50K2p3dCIs...
~~~

The grant is an authorization, not a client credential: redemption
still requires the requester to prove it is the grant's `client_id`,
either by authenticating to this AS as it ordinarily does or, where the
grant carries `cnf`, by proving possession of the bound key. A public
client that can do neither cannot redeem, since nothing then binds the
redemption to the grant's `client_id`. The consuming AS MUST validate,
in an order that fails closed:

1. the JOSE `typ` is `mission-issuance-grant+jwt`; any other type is
   not this profile ({{relationships}}): exact validation of the
   `typ`, with mutually exclusive validation rules for the artifact
   profiles, implements the substitution defense of {{RFC8725}},
   Sections 3.11 and 3.12;
2. the signature, under a `kid` resolving in the published key
   material of an `iss` its local policy trusts for issuance joins;
3. `aud` names this AS; `exp` and `iat` are within the 300-second
   bound; the `jti` has not been seen. The record of a seen `jti` is
   written atomically with successful issuance and retained until
   `exp` passes (single use, {{effective-set-projection}});
4. the requester is the grant's `client_id`: the authenticated client
   equals it, or, where `cnf` is present, the proof of possession of
   step 5 binds the redemption to the key the grant was minted for;
5. when `cnf` is present, proof of possession of the bound key with
   DPoP {{RFC9449}} or mutual TLS {{RFC8705}}.

On success the consuming AS mints tokens under these rules:

- **The claim rides unchanged.** Issued tokens carry the grant's
  `mission` object verbatim as the issuance profile's `mission` claim, including
  the `expires_at` member ({{expires-at-member}}).
- **Subset.** Issued `authorization_details` MUST be a subset of the
  grant's. The consuming AS MUST NOT widen, remap, or supplement
  them from its own policy except to narrow.
- **Echo.** The token response SHOULD echo the issued
  `authorization_details` as the issuance profile specifies for Mission-bound
  issuance.
- **Scope projection.** Carrying `authorization_details` at all
  requires {{RFC9396}} support at the consuming AS. An AS that
  models authority as `scope` instead projects the grant's
  `authorization_details` to `scope` under the issuance profile's
  scope-projection rule ({{I-D.draft-mcguinness-oauth-mission}}):
  every issued scope value corresponds to authority the grant
  conveys, and none conveys authority, or relaxes a constraint, that
  the grant does not.
- **Lifetime.** No access or refresh token issued under the grant may
  have an expiry later than the `mission` object's `expires_at`. That
  ceiling is the Mission horizon, not a liveness bound, so access
  tokens issued under a grant SHOULD be short-lived: absent a
  redemption-time state check, an issued access token's own lifetime is
  the window in which a revoked Mission's token keeps working at the
  token layer.
- **Effective Authority Set projection.** Redemption and every
  refresh are gated on current Mission state and projected through
  the Mission's current Effective Authority Set, per
  {{effective-set-projection}}.
- **No re-approval.** The approval event already occurred at the
  Mission Issuer. The consuming AS MUST NOT prompt the Subject or
  any user for consent at redemption.

A grant redeems exactly once, meaning exactly one successful
issuance: a redemption that fails before issuance leaves the grant
unconsumed ({{effective-set-projection}}). Subsequent token needs are
met by the issued refresh token (state-gated) or a fresh grant
(state-gated at minting); either way, every path to new authority
re-enters a Mission-state gate, which is the issuance-gate kill
switch this profile restores.

## Effective Authority Set Projection {#effective-set-projection}

A consuming AS with a Mission-state integration MUST, at redemption
and at every refresh, resolve the Mission's current state and
Effective Authority Set through the Mission Status operation
({{I-D.draft-mcguinness-oauth-mission-status}}) or an equivalent
authority source, and refuse when the Mission is not established
`active`. An equivalent source MUST be authenticated, MUST be
audience-scoped to this AS, MUST carry the Mission's current
`authorization_details` and a monotonic state `version`, and MUST
answer within a staleness bound the deployment publishes
({{conformance}}).

Where the Mission is `active`, the consuming AS
projects issued authority through the current Effective Authority
Set: the intersection of the grant's `authorization_details` (on
refresh, the refresh family's own ceiling), any narrower authority the
client requests at the token endpoint, that Effective Authority Set,
and the consuming AS's own policy, which narrows only, per the subset
rule above. A partial intersection issues only the remainder. This
projection precedes scope projection above: an AS that models
authority as `scope` maps the narrowed remainder, never the grant's
original set.

An empty intersection is refused by its cause. Where the underlying
authorization is exhausted, that is, where the grant's own authority
intersected with the Effective Authority Set and the AS's policy is
already empty before the request's own narrowing term, the refusal is
`invalid_grant` ({{redemption-errors}}); it MAY carry Containment's
`authority_contained` denial reason where Containment causally removed
the authority, and a collapse from any other cause MUST NOT be
reported as containment merely because Containment is composed
({{I-D.draft-mcguinness-oauth-mission-containment}}). Where that
authorization survives and only the narrowing the client requested
fails to intersect it, the request is at fault: the refusal is
`invalid_scope` where the request carried `scope`, or
`invalid_authorization_details` {{RFC9396}} where it carried
`authorization_details`.

The Mission Status operation discharges the source properties above
directly: an authenticated, audience-scoped Mission Status Response,
queried with this AS's own audience, carries current
`authorization_details` and the Mission's state `version`
({{I-D.draft-mcguinness-oauth-mission-status}}). Whatever the source,
an active Mission state, or a Status List VALID bit, does not alone
satisfy this: containment and discharge narrow an active Mission
without moving its lifecycle state, and the Status List's bit carries
no `authorization_details` at all.

A source that is unavailable, fails verification, or reports a state
`version` older than one already observed for this Mission is a
transient failure, never authority exhaustion, and is refused in a
machine-readable shape: this profile defines a token-endpoint use of
the OAuth `temporarily_unavailable` error code {{RFC6749}}, carried
with HTTP status 503, and the response MAY carry `Retry-After` per the
deployment's declared state-recovery policy ({{redemption-errors}}).
The consuming AS leaves its stored ceiling unchanged. `invalid_grant`
stays for the permanent classes: an invalid, expired, or replayed
grant, a Mission that is not established `active`, and a genuinely
empty current intersection.

Consumption is atomic with issuance. The single-use `jti` check of
{{redemption}} refuses a grant already recorded; the record itself is
written atomically with successful issuance, after the state gate and
this projection. A redemption that fails before issuance, a transient
source failure in particular, therefore leaves the grant unconsumed
and retryable, and concurrent redemptions of one grant are resolved by
that atomic record: the loser is a replay, refused `invalid_grant`. On
the refresh path a transient source failure MUST NOT consume or rotate
the presented refresh token, so the client retries with the credential
it already holds.

A refresh family's issued authority MUST NOT widen across refreshes
within the same Mission: the consuming AS atomically narrows its own
stored ceiling on every refresh, or retains the highest Mission state
`version` it has observed and rejects a source reporting a lower one
as a rollback.

A consuming AS without a Mission-state integration MUST NOT issue
refresh tokens under a grant, and relies instead on the grant's
`active`-at-minting gate and the short access-token lifetime above. A
consuming AS that issues refresh tokens strengthens that integration
from a lifecycle-state check to this authority-capable form:
reporting Mission state alone no longer suffices. A consuming AS
that cannot perform this projection MUST NOT claim containment- or
discharge-aware issuance.

## Redemption Errors {#redemption-errors}

The consuming AS reports redemption failures with the token endpoint's
OAuth error codes {{RFC6749}}, so a client can tell a retryable grant
problem from a dead Mission:

| Failure | `error` |
|---|---|
| `typ` is not `mission-issuance-grant+jwt` | `invalid_grant` |
| `iss` is not trusted for issuance joins | `invalid_grant` |
| `aud` does not name this AS | `invalid_grant` |
| grant expired, or `jti` already seen (replay) | `invalid_grant` |
| grant authority unmappable to this AS's resources | `invalid_grant` |
| grant `sub` unmappable to a local account | `invalid_grant` |
| client authentication fails | `invalid_client` |
| authenticated client is not the grant's `client_id` | `invalid_grant` |
| `cnf` proof of possession fails | `invalid_grant` |
| refresh refused because the Mission is not `active` | `invalid_grant` |
| the surviving authorization is exhausted: the intersection is empty before the request's own narrowing ({{effective-set-projection}}) | `invalid_grant` |
| the client's requested narrowing does not intersect surviving authority, `scope` form ({{effective-set-projection}}) | `invalid_scope` |
| the same, `authorization_details` form ({{effective-set-projection}}) | `invalid_authorization_details` |
| the Effective Authority Set source is unavailable, unverifiable, or reports a rolled-back state version ({{effective-set-projection}}) | `temporarily_unavailable`, HTTP 503 |

The distinctions the client needs are retry as is, get a fresh grant,
and the Mission is dead:

- **Retry as is.** `temporarily_unavailable` with HTTP 503 is
  machine-readable: the authorization is intact and the same
  credential may be presented again, without parsing
  `error_description`.
- **Get a fresh grant.** Most `invalid_grant` cases fall here: the
  client mints a fresh grant ({{minting}}) and retries.
- **The Mission is dead.** The dead-Mission case is a refresh refused
  on a non-active Mission; there the AS SHOULD make the response
  distinguishable with an `error_description` stating the Mission is
  not active, and a client that re-mints will in any case be refused
  at the MAS `active` gate with `mission_not_active`
  ({{minting-errors}}), which is the authoritative signal to stop
  rather than retry.

`invalid_scope` and `invalid_authorization_details` name a request the
client can narrow and re-send under the same grant.

## Authorization Code Flow Carriage {#par-carriage}

Deployments whose clients must traverse the authorization code flow
MAY carry the grant in a Pushed Authorization Request {{RFC9126}} as
the request parameter `mission_issuance_grant` ({{iana}}).

The AS applies the grant validation of {{redemption}} at the PAR
endpoint and treats the grant as the authorization already obtained.
It MUST NOT re-prompt for consent; at most it renders the Mission
reference.

The AS consumes the grant at PAR validation: the 300-second `exp`,
`iat`, and `aud` checks and the single-use `jti` check are evaluated
there, and the `jti` is recorded as seen at that point, so the grant
cannot be replayed into a second authorization request. Recording
there is the atomic issuance step of {{effective-set-projection}}
under this carriage, because the issued authorization code becomes the
grant's carrier from that point on.

The grant's window is not re-evaluated at code exchange; the issued
authorization code carries its own lifetime from there. All
remaining redemption rules (subset, lifetime, Effective Authority Set
projection, no re-approval, and the error mapping of
{{redemption-errors}}) apply at the token request unchanged. A
transient source failure at code exchange refuses
`temporarily_unavailable` and MUST NOT consume the authorization code,
so the exchange stays retryable within the code's own lifetime.

This carriage serves user-delegated Missions
({{I-D.draft-mcguinness-oauth-mission}}), where an authenticated
resource owner exists to bind. The AS MUST bind the resource owner
authenticated at the authorization endpoint to the grant's `sub`: it
proceeds only where the authenticated user is the grant's Subject
under the deployment's mapping policy ({{issuance-join}}). The AS
MUST refuse when a different user authenticates, so the grant cannot
mint tokens for the wrong resource owner.

For a service-owned or organizational Mission there is no delegating
user to authenticate; such a grant is redeemed directly
({{redemption}}), not carried through the authorization code flow.
The authenticated client MUST still be the grant's `client_id`
({{redemption}}).

# Relationship to Other Artifacts {#relationships}

**The Mandate is evidence; this grant authorizes.** Both are
issuer-signed statements about a Mission; the `typ` values keep them
apart mechanically, and a verifier of either MUST reject the other
({{I-D.draft-mcguinness-mission-mandate}}).

**The cross-domain grant is this shape across a trust boundary.**
Cross-domain projection
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}) carries a
Mission to a Resource AS in another domain, with trust established
by federation agreement and identity chaining. The issuance join is
the same-estate case: bilateral, pre-configured trust between a MAS
and its own Authorization Servers, no identity-chaining substrate
required. A deployment does not use this profile across domains;
projection exists for that.

**Native Mission-aware issuance retires this grant; it does not rank
the architectures.** An AS that
becomes natively Mission-aware implements the issuance profile and mints without
grants for its own resources; the record, anchors, and lifecycle it
consumes are the same ones the MAS already operates, so nothing is
re-approved in migration. Until then, the issuance join gives the
estate Mission-bound tokens at a fraction of the issuance profile's
implementation surface.

**The runtime join remains for everything else.** Tokens minted
under this profile compose credential-carried at the PDP; ordinary
tokens continue to compose through the Mission Join. The two joins
coexist per resource and per AS.

# Composite Provision {#composite}

In the substrate's terms ({{I-D.draft-mcguinness-mission-substrate}})
the MAS alone claims neither Credential-Bound nor Lifecycle-Gated
Authorization for the tokens its unchanged Authorization Servers
issue. A MAS composed with its consuming Authorization Servers under
this profile supplies both capabilities, jointly, for the resources
those ASs serve. In the Mission Assurance Levels
({{I-D.draft-mcguinness-mission-architecture}}), Baseline Issuance
and its issuance-gate kill switch become reachable under the
standalone binding through this profile, and the state-aware
half-step arrives with the consuming AS's refresh gating.

# Conformance {#conformance}

**Grant Minter** (the MAS) implements {{minting}} in full:

- the authenticated, visibility-guarded endpoint;
- the `active`-only gate;
- subset and audience scoping;
- derivation counting where consented;
- minting evidence; and
- grants shaped exactly as {{grant}} requires.

**Consuming Authorization Server** implements {{redemption}} in
full:

- `typ`, signature, audience, lifetime, single-use, and client
  binding validation;
- verbatim `mission` claim carriage;
- subset-bounded minting;
- `expires_at` capping;
- Effective Authority Set projection at redemption, which binds every
  state-integrated consuming AS unconditionally
  ({{effective-set-projection}});
- Effective Authority Set projection at every refresh, which binds a
  consuming AS that issues refresh tokens; a no-refresh deployment
  discharges this duty by absence ({{effective-set-projection}});
- no re-approval; and
- the redemption error mapping of {{redemption-errors}}.

The PAR carriage of {{par-carriage}} is OPTIONAL.

A deployment claiming this profile states, alongside its
Enforcement Scope Statement, which Authorization Servers consume
grants, the staleness bound of each one's state gating, and its
reconciliation posture ({{security-considerations}}): the window
within which minting and redemption logs are reconciled, or that
they are not. A consuming AS advertises its support with the
`mission_issuance_grant_supported` metadata member, and its PAR
carriage with `mission_issuance_grant_par_supported` ({{iana}}).

# Security Considerations {#security-considerations}

**Grant theft.** The grant authorizes issuance, so it is defended in
depth: 300-second lifetime, single-use `jti`, audience binding to
one AS, redemption bound to the Mission's authenticated `client_id`,
and optional `cnf` key binding. A stolen grant is useless to any
party that cannot also authenticate as the recorded client at the
named AS within the window; deployments whose client credentials are
weak SHOULD require `cnf` (DPoP {{RFC9449}} or mTLS {{RFC8705}}
bindings serve).

**Mission Issuer compromise reaches issuance.** In MAS-only
deployment, MAS compromise corrupts records and state. Under this
profile it additionally mints grants every consuming AS honors:
compromise reaches token issuance across the estate. The consuming
ASs' audit logs of redeemed grants (each with `jti` and Mission
reference) are the independent record that bounds and exposes such
minting.

A deployment SHOULD reconcile MAS minting evidence against
consuming-AS redemption logs. A deployment SHOULD treat a redemption
with no matching minting record as a security event. A deployment
states its reconciliation posture in its conformance statement
({{conformance}}). A deployment operating under the Enterprise
Mission Authority Profile
({{I-D.draft-mcguinness-mission-authority-server}}) MUST reconcile
within the window its statement declares; at estate scale,
reconciliation is the only check on this compromise class.

**Trust inversion.** The consuming AS accepts externally derived
authority. Its exposure is bounded by the profile's own rules: it
mints only within the grant's `authorization_details`, only for the
grant's client, never longer than the Mission's `expires_at`, and
its local
policy MAY narrow further. The AS remains free to refuse any grant
its policy distrusts; nothing obliges issuance.

**Type confusion.** Three issuer-signed JWT artifacts about Missions
now exist: the Mandate (evidence), the cross-domain grant (foreign
domain), and this grant (same estate). The `typ` discipline is the
defense; every consumer checks it first, and none accepts another's
type.

**Revocation latency.** New grants stop at the MAS `active` gate at
the moment of state commit. Outstanding tokens end at the earlier of
their own expiry and the consuming AS's next state-gated refresh;
where the runtime layer is deployed, the PDP's re-check bounds
outstanding-token use independently. A refresh re-projects through
the Effective Authority Set ({{effective-set-projection}}), so a
Mission contained or discharged between issuance and refresh does
not renew its original, now-narrowed authority. A deployment states
the refresh staleness bound it publishes ({{conformance}}).

**Consent integrity.** The approval the grant rests on was rendered
and committed at the Mission Issuer under the issuance profile's rules and,
where deployed, Consent Evidence. The consuming AS relies on that
event; it MUST NOT substitute a weaker consent of its own, and its
non-prompting duty ({{redemption}}) prevents consent-surface
confusion where the Subject holds accounts at both.

# Privacy Considerations {#privacy-considerations}

The grant carries the Mission reference and an authority subset to
the consuming AS, which may be operated by a different organizational
unit than the MAS. Minimization is structural: the MAS scopes
`authorization_details` to what the audience serves ({{minting}}),
and nothing else of the record (no `purpose` text, no Intent, no full
Authority Set) travels. The Mission identifier is a correlator across
MAS and AS logs by design; that correlation is the audit trail, and
deployments that need to limit broader correlation apply the
issuance profile's identifier guidance.

# IANA Considerations {#iana}

## Media Type Registration

IANA is requested to register one media type per {{RFC6838}}.

### application/mission-issuance-grant+jwt

- Type name: application
- Subtype name: mission-issuance-grant+jwt
- Required parameters: none
- Optional parameters: none
- Encoding considerations: binary; JWS Compact Serialization
- Security considerations: see {{security-considerations}}
- Interoperability considerations: see this document
- Published specification: this document
- Applications that use this media type: Mission Authority Servers
  and OAuth Authorization Servers implementing this profile
- Fragment identifier considerations: n/a
- Additional information: n/a
- Person and email address to contact for further information: see
  the Authors' Addresses section
- Intended usage: COMMON
- Restrictions on usage: none
- Author: see the Authors' Addresses section
- Change controller: IETF

## Mission Authority Server Metadata Registration

IANA is requested to register the following in the "Mission
Authority Server Metadata" registry established by
{{I-D.draft-mcguinness-mission-authority-server}}. Change Controller
IETF; Reference this document, {{minting}}.

- `mission_issuance_grant_endpoint`

## OAuth Authorization Request Parameter Registration

IANA is requested to register the following in the "OAuth Parameters"
registry {{RFC6749}}, for the parameter carried in Pushed Authorization
Requests ({{par-carriage}}):

- Parameter name: `mission_issuance_grant`
- Parameter usage location: authorization request
- Change Controller: IETF
- Reference: this document, {{par-carriage}}

## OAuth Authorization Server Metadata Registration

IANA is requested to register the following in the "OAuth Authorization
Server Metadata" registry {{RFC8414}}, so a consuming AS can signal its
support. Change Controller IETF; Reference this document, {{redemption}}
for the first and {{par-carriage}} for the second:

- `mission_issuance_grant_supported`: a JSON boolean; `true` when the
  AS redeems Mission Issuance Grants at its token endpoint.
- `mission_issuance_grant_par_supported`: a JSON boolean; `true` when
  the AS accepts the `mission_issuance_grant` parameter in Pushed
  Authorization Requests.

--- back

# Acknowledgments
{:numbered="false"}

This document profiles the JWT authorization grant of RFC 7523 and
composes the Mission Authority Server with the issuance profile it
already mirrors; it defines no cryptography of its own.
