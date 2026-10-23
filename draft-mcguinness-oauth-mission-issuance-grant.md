---
title: "Mission Issuance Grant for OAuth 2.0"
abbrev: "OAuth Mission Issuance Grant"
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
  RFC3339:
  RFC6838:
  RFC7515:
  RFC7519:
  RFC7523:
  RFC7800:
  RFC8414:
  RFC8705:
  RFC9101:
  RFC9126:
  RFC9396:
  RFC9449:
  RFC8693:
  RFC9728:
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
  I-D.draft-mcguinness-oauth-mission-derivation-limits:
    title: "Mission Derivation Limits for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-derivation-limits.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

informative:
  I-D.draft-mcguinness-oauth-mission-resource-access:
    title: "Mission Resource Access Profile for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-resource-access.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  RFC8628:
  RFC8725:
  I-D.draft-ietf-oauth-rfc7523bis:

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

--- abstract

This specification defines the Mission Issuance Grant, a profile of
the JSON Web Token (JWT) authorization grant of RFC 7523. A Mission
Authority Server, which approves and records Missions without
changing an estate's OAuth authorization servers, issues the grant
for an active Mission: a short-lived, single-use JWT for one client
and one authorization server. The client presents it at that
authorization server's token endpoint and receives Mission-bound
tokens, which carry the Mission, are bounded by the authority the
grant conveys, and expire no later than the Mission. An authorization
server that checks Mission state at redemption and at every refresh
stops issuing and renewing those tokens once the Mission is no longer
active, and narrows them when its authority is narrowed; one that
does not issues no refresh tokens. Approval, the Mission record, and
its lifecycle stay at the Mission Authority Server.

--- middle

# Introduction

Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} (the "issuance profile") binds
issued authority to a durable, human-approved Mission, with the
authorization server (AS) as the Mission Issuer. The Mission Authority
Server (MAS, {{I-D.draft-mcguinness-mission-authority-server}}) hosts
the same Mission without changing the estate's authorization servers:
it validates Mission Intents, runs approval, records Missions, and
operates their lifecycle. The tokens those authorization servers issue
remain ordinary. They do not carry the Mission, and their issuance
and refresh do not depend on Mission state; enforcement can relate
them to a Mission only at the point of use, through the Mission Join.

This specification defines the **issuance join**, in which the MAS
remains the Mission Issuer and an estate's AS issues Mission-bound
tokens. The carrier is the **Mission Issuance Grant**, a JWT the MAS
issues for an active Mission and the client presents to the AS as a
JWT authorization grant {{RFC7523}}. RFC 7523 defines how a client
presents a JWT as an authorization grant and how the AS validates it.
This profile defines what the grant contains, how the MAS issues it,
what the AS issues in return, and how the AS keeps issuance and
refresh bounded by the Mission's current state and authority.

Every grant is minted against current Mission state, so a Mission
that is not active receives no new grants. An AS with a Mission-state
integration ({{conventions}}) also checks the Mission at redemption
and at every refresh; one without issues no refresh tokens. Either
way, every path to new tokens passes a Mission-state check, an
issuance gate a MAS alone does not provide
({{I-D.draft-mcguinness-mission-authority-server}}). Where that check
is the grant's minting, the grant's remaining lifetime adds to the
issued token's ({{security-considerations}}).

The AS implements none of the issuance profile's intake, approval
ceremony, authority derivation, record, or lifecycle surfaces; those
stay at the MAS. A deployment can adopt the issuance join at some
authorization servers and keep the Mission Join at others
({{relationships}}).

# Conventions and Terminology {#conventions}

{::boilerplate bcp14-tagged}

This document uses Mission, Mission Intent, Authority Set, Mission
Issuer, the `mission` claim, the subset rule, and the integrity
anchor `authority_hash` as the issuance profile defines them; Mission
Authority Server (MAS), Mission Join, and the Enterprise Mapping
Contract as {{I-D.draft-mcguinness-mission-authority-server}} defines
them; and Effective Authority Set as
{{I-D.draft-mcguinness-oauth-mission-status}} defines it. Under this
profile the MAS is the Mission Issuer. It additionally uses:

Issuance join:
: The integration this document defines: a MAS-approved Mission
  carried by a grant that an authorization server redeems at its
  token endpoint.

Mission Issuance Grant (grant):
: The signed assertion of {{grant}}, issued by the MAS and redeemed
  for Mission-bound tokens.

Consuming Authorization Server (consuming AS):
: An OAuth authorization server {{RFC6749}} that redeems Mission
  Issuance Grants at its token endpoint; conformance role of
  {{conformance}}.

Mission-state integration:
: A consuming AS's means of resolving the Mission's current state and
  Effective Authority Set at redemption and at every refresh
  ({{mission-state-source}}). A consuming AS either has one and
  applies {{effective-set-projection}}, or has none and issues no
  refresh tokens under a grant ({{no-state-integration}}).

Refresh family:
: The refresh tokens descended from one redemption of a grant (under
  the authorization code flow carriage, one code exchange), including
  every rotation, and the authorization they carry.

Family ceiling:
: The remaining authority a consuming AS persists for a refresh
  family ({{refresh}}): after each successful issuance, the surviving
  authority of that issuance (items 1 to 3 of {{issued-authority}}). A
  narrowing the client requests at the token endpoint does not reduce
  it, and it is not the contents of the last access token issued for
  one audience.

# The Issuance Join {#issuance-join}

## Protocol Flow {#protocol-flow}

The following figure shows the issuance join between the client, the
MAS, and a consuming AS:

~~~
  Client                     MAS                       Consuming AS
    |                         |                              |
    |-- (A) grant request --->|                              |
    |<-- (B) grant -----------|                              |
    |                         |                              |
    |-- (C) token request with the grant ------------------->|
    |                         |<-- (D) Status, per audience -|
    |                         |--- state and Effective ----->|
    |                         |    Authority Set             |
    |<-- (E) access token (and refresh token) ---------------|
    |                         |                              |
    |-- (F) refresh request -------------------------------->|
    |                         |<-- (D) repeated -------------|
    |<-- (E) new tokens -------------------------------------|
~~~

(A) The client requests a grant from the MAS for an active Mission,
    naming the consuming AS as the audience ({{minting}}).

(B) The MAS returns a grant bound to that AS and to the client, and
    carrying a subset of the Mission's current authority ({{grant}}).

(C) The client presents the grant at the consuming AS's token
    endpoint as a JWT authorization grant ({{redemption}}).

(D) A consuming AS with a Mission-state integration resolves the
    Mission's current state and Effective Authority Set, with one
    Mission Status request per audience the grant's entries are
    relevant to ({{effective-set-projection}}).

(E) The consuming AS issues Mission-bound tokens within the grant's
    authority and that set ({{token-issuance}}).

(F) Each refresh repeats (D) before (E). A consuming AS without a
    Mission-state integration skips (D) and issues no refresh token
    ({{no-state-integration}}).

## Trust {#trust}

Trust is pre-established and bilateral. A consuming AS accepts
grants only from Mission Issuers its local policy names, resolving
their signing keys from the MAS's `jwks_uri`
({{I-D.draft-mcguinness-mission-authority-server}}); a MAS mints
grants only for authorization servers its configuration names as
audiences. The deployment's mapping policy governs how a grant's
(`iss`, `sub`) pair and `client_id` correspond to the consuming AS's
accounts; where the Enterprise Mission Authority Profile is claimed,
the Enterprise Mapping Contract governs
({{I-D.draft-mcguinness-mission-authority-server}}). The audiences
the MAS scopes a consuming AS's grants to ({{minting-rules}}) are the
audiences it authorizes that AS to request from Mission Status
({{mission-state-source}}). The issuance join is the same-estate case:
a deployment does not use it across domains, where cross-domain
projection applies instead ({{relationships}}).

The MAS holds the approval event, the record and its anchors, the
lifecycle, and grant minting. The consuming AS holds client
authentication, token issuance bounded by the grant, and refresh.

# The Mission Issuance Grant {#grant}

A Mission Issuance Grant is a JWT {{RFC7519}} signed as a JWS
{{RFC7515}} by the Mission Issuer. Its JOSE header MUST carry the
`typ` header parameter with the value `mission-issuance-grant+jwt`
({{iana}}) and a `kid` that resolves in the Mission Issuer's
published key material.

Claims:

`iss`:
: REQUIRED. The Mission's `issuer`: the MAS issuer URL.

`sub`:
: REQUIRED. The Mission's Subject as a MAS-local identifier, which the
  MAS maps from the recorded (`subject.iss`, `subject.sub`) pair
  before minting ({{minting-rules}}). The consuming AS interprets the
  (`iss`, `sub`) pair under the deployment's mapping policy
  ({{trust}}).

`aud`:
: REQUIRED. The consuming AS's issuer identifier {{RFC8414}}, as a
  single string ({{grant-validation}}). This restricts
  {{Section 3 of RFC7523}}, under which a token endpoint URL can also
  identify the AS; Section 4 of {{I-D.draft-ietf-oauth-rfc7523bis}}
  keeps both forms for authorization grants.

`iat`, `exp`:
: REQUIRED. `exp` MUST NOT be more than 300 seconds after `iat`.

`jti`:
: REQUIRED. Unique per grant; single use ({{single-use}}).

`client_id`:
: REQUIRED. The Mission's recorded agent client identifier as the
  consuming AS knows it ({{Section 4.3 of RFC8693}}); the MAS sets it
  under the deployment's mapping policy ({{trust}}). Only this client
  can redeem the grant ({{redemption}}).

`mission`:
: REQUIRED. The issuance profile's `mission` claim object, with the
  members {{mission-claim}} requires.

`authorization_details`:
: REQUIRED. Authorization details {{RFC9396}} that the consuming AS
  issues against, of the types {{entry-types}} admits: a subset of the
  Mission's Effective Authority Set, limited to the entries this AS
  serves ({{minting-rules}}).

`cnf`:
: OPTIONAL. A confirmation claim {{RFC7800}} binding redemption to a
  key: the `jkt` member for OAuth 2.0 Demonstrating Proof of
  Possession (DPoP, {{Section 6.1 of RFC9449}}), or the `x5t#S256`
  member for mutual TLS ({{Section 3.1 of RFC8705}}). The MAS sets it
  as {{minting-rules}} requires, and the consuming AS verifies it as
  {{grant-validation}} requires.

The following is an example of a decoded grant payload for the
Mission of the examples in
{{I-D.draft-mcguinness-mission-authority-server}}. Its entry is a
subset of that Mission's invoice-read entry, and its `sub` is the
recorded `subject.sub` copied verbatim, which {{minting-rules}}
permits where it collides with no other principal's `sub`. The request
example of {{minting-request}} presents a DPoP proof, so the grant's
`cnf` carries that key:

~~~ json
{
  "iss": "https://mas.example.com",
  "sub": "user_3p2q8mN1a0kV7tR",
  "aud": "https://as.example.com",
  "iat": 1793606400,
  "exp": 1793606580,
  "jti": "mig_7Kq2Rv9Lp4xW1nT8",
  "client_id": "s6BhdRkqt3",
  "cnf": { "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" },
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "issuer": "https://mas.example.com",
    "authority_hash":
      "sha-256:rspctkzaH13fMUjC6FxL5npl9HREFVrQIk0WN8O_CGs",
    "expires_at": "2026-12-31T23:59:59Z"
  },
  "authorization_details": [
    {
      "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["invoices.read"],
      "constraints": {
        "resource_issued_after": "2026-07-01T00:00:00Z",
        "resource_issued_before": "2026-09-30T23:59:59Z"
      }
    }
  ]
}
~~~

## The `mission` Claim {#mission-claim}

The grant's `mission` claim is the issuance profile's `mission` claim
object ({{I-D.draft-mcguinness-oauth-mission}}, Section "Mission
Claim"), with two members that object does not otherwise require:

- **`expires_at`.** REQUIRED here, although OPTIONAL in the issuance
  profile's claim. The Lifetime rule ({{token-issuance}}) caps every
  token issued under the grant at this value.
- **`authority_hash`.** The `mission` object MUST carry
  `authority_hash` ({{I-D.draft-mcguinness-oauth-mission}}, Section
  "Integrity Anchors"), which the issuance profile's baseline claim
  omits. It names the approved Authority Set the grant derives from,
  for a consuming AS that, without a Mission-state integration, has
  no other channel back to the Mission Issuer. The consuming AS
  records it with each issuance ({{records}}) and does not verify it.

## Entry Types {#entry-types}

A grant's `authorization_details` can carry entries of any type that
both the MAS and the consuming AS support
({{I-D.draft-mcguinness-oauth-mission}}, Section "Authorization
Details Types"; the MAS's supported types are those its deployment
documentation names); this profile requires no particular type. Each
entry's audience relevance, subset relation, and transformations
follow its type's specification and the transformation capabilities
each party declares for that type, through the carriers that section
lists, deployment documentation among them. A consuming AS
serves an entry that, under its type, is relevant to an audience for
which that AS issues tokens. For example, a `mission_resource_access`
entry ({{I-D.draft-mcguinness-oauth-mission-resource-access}}) is
relevant to the audience its `resource` member names.

Omitting a whole entry always yields a subset. Narrowing within an
entry, or projecting it to `scope`, needs the corresponding declared
capability, and neither party performs a transformation it has not
declared for the entry's type. An operation this document calls for
that a party cannot perform fails closed:

- The MAS MUST refuse, with `invalid_authorization_details`
  ({{minting-errors}}), a grant request whose requested narrowing it
  cannot perform.
- The consuming AS MUST refuse, with `invalid_grant`, a grant that
  carries an entry of a type it does not support
  ({{grant-validation}}).
- The consuming AS MUST NOT issue an entry it cannot narrow except
  unchanged, where the current Effective Authority Set and its own
  policy each contain an entry equal to it under the subset rule;
  otherwise it omits the entry ({{issued-authority}}).
- The consuming AS MUST refuse a requested narrowing it cannot
  perform with `invalid_authorization_details`. It refuses a `scope`
  projection it cannot perform as the issuance profile maps that
  failure (`invalid_target`, {{I-D.draft-mcguinness-oauth-mission}},
  Section "Error and Challenge Mapping").

# Obtaining a Grant {#minting}

A MAS implementing this profile serves a Mission Issuance Grant
endpoint, published as `mission_issuance_grant_endpoint` in its
metadata ({{metadata}}).

## Grant Request {#minting-request}

The requester sends an HTTP POST request with an `application/json`
body to the endpoint, which has the TLS and client-authentication
requirements of the MAS's Mission submission endpoint
({{I-D.draft-mcguinness-mission-authority-server}}, Section "Mission
Submission") with this endpoint in its place: an access token's
audience names this endpoint, and the MAS publishes Protected
Resource Metadata {{RFC9728}} for it, naming its resource, required
scope, accepted sender constraints, and DPoP algorithms
(`dpop_signing_alg_values_supported`). The MAS ignores body members
it does not recognize. The body carries:

`mission_id`:
: REQUIRED. A string. The Mission the grant is minted for; its
  `issuer` is this MAS.

`audience`:
: REQUIRED. A string. The issuer identifier of the consuming AS the
  grant is for. The MAS compares it literally with the issuer
  identifiers its configuration names and sets the grant's `aud` to
  the matching identifier ({{trust}}).

`authorization_details`:
: OPTIONAL. An array. A narrower subset the requester asks the grant
  to carry, under the issuance profile's subset rule. If it is
  omitted, the MAS scopes the grant to the entries the named audience
  serves ({{minting-rules}}); if it is present, it MUST NOT widen
  beyond that scope.

`client_id`:
: CONDITIONAL. A string, REQUIRED with mutual-TLS client
  authentication, as Mission Status requires for that mechanism
  ({{I-D.draft-mcguinness-oauth-mission-status}}, Section
  "Authentication").

`client_assertion_type`:
: CONDITIONAL. A string, present exactly when the requester
  authenticates with a private-key JWT: the value
  `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
  ({{Section 2.2 of RFC7523}}).

`client_assertion`:
: CONDITIONAL. A string, present exactly when `client_assertion_type`
  is: the client-authentication JWT. These two members carry as JSON
  strings the values {{Section 2.2 of RFC7523}} defines as form
  parameters, and the MAS processes them as Mission Status's
  private-key-JWT mechanism requires
  ({{I-D.draft-mcguinness-oauth-mission-status}}, Section
  "Authentication"), with the MAS's issuer identifier as the
  assertion's sole `aud`.

A requester obtains a key-bound grant by presenting a sender
constraint on the request: a DPoP proof ({{Section 4 of RFC9449}}) in
the `DPoP` header field, with `htm` `POST`, `htu` the endpoint URL,
and `ath` only where a DPoP-bound access token authenticates the
request, which the MAS checks as {{Section 4.3 of RFC9449}} requires;
or the client certificate of a mutual-TLS connection {{RFC8705}}.
Neither is client authentication by itself. The MAS MUST verify any
DPoP proof presented with the request and refuses a request whose
proof fails ({{minting-errors}}). A client that does not want its
connection certificate bound presents a DPoP proof, which takes
precedence ({{minting-rules}}).

The following is an example of a grant request that authenticates
with a private-key JWT in the body and presents a DPoP proof for key
binding:

~~~ http-message
POST /mas/mission/issuance-grant HTTP/1.1
Host: mas.example.com
Content-Type: application/json
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2Iiwi...

{
  "mission_id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
  "audience": "https://as.example.com",
  "authorization_details": [
    {
      "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["invoices.read"],
      "constraints": {
        "resource_issued_after": "2026-07-01T00:00:00Z",
        "resource_issued_before": "2026-09-30T23:59:59Z"
      }
    }
  ],
  "client_assertion_type":
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
  "client_assertion": "eyJhbGciOiJFUzI1NiIsImtpZCI6IjE2In0..."
}
~~~

## Grant Processing {#minting-rules}

The MAS MUST apply the following rules:

1. **Requester.** The MAS authenticates the requester as its Mission
   submission endpoint does
   ({{I-D.draft-mcguinness-mission-authority-server}}, Section
   "Mission Submission"), with the client assertion carried in the
   JSON body where it uses private-key JWT ({{minting-request}}). The
   requester MUST be the Mission's
   recorded client. Any other caller, including a delegate or
   enforcement point that the Mission Join Assertion endpoint admits,
   receives `not_found` ({{minting-errors}}).
2. **State gate.** The MAS mints a grant only while its own record
   shows the Mission `active`, and otherwise refuses.
3. **Subset and audience.** The grant's `authorization_details` MUST
   be a subset, under the issuance profile's subset rule
   ({{I-D.draft-mcguinness-oauth-mission}}, Section "Subset Rule"), of
   the Mission's current Effective Authority Set
   ({{I-D.draft-mcguinness-oauth-mission-status}}), so a contained
   capability is absent from it
   ({{I-D.draft-mcguinness-oauth-mission-containment}}, Section
   "Derivation Gating"). The grant MUST carry only the entries the
   named consuming AS serves. The requester MAY request a narrower
   subset. The MAS MUST refuse a request for a wider one.
4. **Derivation event.** Each grant minted is a derivation event.
   Where the Mission's established `derivation_limit` is set, the MAS
   MUST count grants against it atomically and refuse beyond it, as
   {{I-D.draft-mcguinness-oauth-mission-derivation-limits}}, Section
   "Mission Issuance Grant Minting", defines; redemption and refresh
   at a consuming AS are not counted.
5. **Key binding.** When the MAS verified a sender constraint on the
   grant request ({{minting-request}}), it MUST include `cnf` with that
   key: the public key of the request's DPoP proof, as `jkt`, or,
   where the request carries no DPoP proof, the certificate of the
   mutual-TLS connection, as `x5t#S256`, whether or not that
   certificate also authenticated the client. When the MAS includes
   `cnf`, it MUST take the key from a sender constraint it verified on
   the grant request. The MAS MUST NOT derive `cnf` solely from
   client-assertion authentication:
   a client assertion authenticates the client, and DPoP is not client
   authentication ({{Section 3 of RFC9449}}), so the binding comes
   only from a sender constraint verified independently on the
   request, even where its key is the one the assertion used. A
   request with no verified sender constraint yields a grant without
   `cnf`, which a public client cannot redeem ({{redemption}}).
6. **Subject.** The MAS MUST derive the grant's `sub` from the
   Mission's recorded (`subject.iss`, `subject.sub`) pair by an
   injective mapping established before it mints, as the issuance
   profile requires of an AS for an external Subject
   ({{I-D.draft-mcguinness-oauth-mission}}, Section "Subject
   Establishment"). Two home issuers can both name a principal
   `alice`, and the mapping keeps them apart. The mapping is stable:
   every grant for one Subject carries the same `sub`. Copying
   `subject.sub` verbatim is valid only where it collides with no
   other principal's `sub` at this MAS. Every Mission has a Subject, a
   service-owned or
   organizational Mission included
   ({{I-D.draft-mcguinness-oauth-mission}}, Section "Authority
   Sources").

## Grant Response {#minting-response}

On success the endpoint returns HTTP 200 with an `application/json`
object:

`grant`:
: REQUIRED. A string. The Mission Issuance Grant JWT of {{grant}}. Its
  `exp` bounds redemption ({{grant-validation}}).

`expires_in`:
: REQUIRED. A JSON integer. The number of whole seconds from the
  generation of the response until the grant's `exp`, rounded down so
  that it never indicates a time after `exp`.

The following is an example of a grant response:

~~~ http-message
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "grant": "eyJ0eXAiOiJtaXNzaW9uLWlzc3VhbmNlLWdyYW50K2p3dCIs...",
  "expires_in": 180
}
~~~

## Grant Errors {#minting-errors}

A failure returns the MAS error object
({{I-D.draft-mcguinness-mission-authority-server}}, Section "Error
Responses") with one of the following `error` codes, which this
document defines for this endpoint. A 401 response carries the
`WWW-Authenticate` challenges that section defines for the MAS's
endpoints, naming this endpoint's Protected Resource Metadata.

| `error` | HTTP | Condition |
|---|---|---|
| `invalid_request` | 400 | A missing or malformed member, or an unparseable body |
| `invalid_client` | 400 | Direct client authentication (mutual TLS or private-key JWT) failed, only one of `client_assertion_type` and `client_assertion` is present, or no credential was presented where no access-token scheme is accepted |
| `invalid_dpop_proof`, `use_dpop_nonce` | 400 | A DPoP proof presented for key binding ({{minting-request}}), with no DPoP-bound access token authenticating the request, fails the checks of {{Section 4.3 of RFC9449}}, carries `ath`, or lacks a nonce the MAS requires ({{Section 8 of RFC9449}}); a proof that constrains an authenticating access token fails as `unauthorized` |
| `unauthorized` | 401 | Access-token authentication failed, or no credential was presented where an access-token scheme is accepted |
| `not_found` | 404 | Unknown `mission_id`, or the requester is not the Mission's recorded client |
| `invalid_audience` | 400 | `audience` names no AS this MAS issues grants for |
| `mission_not_active` | 409 | The Mission is not `active` |
| `invalid_authorization_details` | 400 | The request is wider than the Effective Authority Set or the audience's scope, or asks for a narrowing the MAS cannot perform ({{entry-types}}) |
| `derivations_exhausted` | 409 | The Mission's `derivation_limit` is reached |
| `rate_limited` | 429 | The requester is rate-limited |
| `unavailable` | 503 | The MAS temporarily cannot serve the request |

`not_found` covers both an unknown Mission and a requester that is
not the recorded client, so the response is not a membership oracle.
`invalid_audience`, `mission_not_active`,
`invalid_authorization_details`, and `derivations_exhausted` reach
only the authenticated recorded client, to which Mission state is
already visible. `mission_not_active` is returned during a suspension
and after termination alike; the Mission's state tells the two apart.
`derivations_exhausted` reports the condition the `mission_error`
value of that name reports at a token endpoint
({{I-D.draft-mcguinness-oauth-mission-derivation-limits}}), and no
fresh grant under that Mission cures it.

# Redemption {#redemption}

The client presents the grant to the consuming AS's token endpoint
as a JWT authorization grant {{RFC7523}}. The following example shows
a confidential client that authenticates with a JWT
({{Section 2.2 of RFC7523}}) and proves possession of the grant's
`cnf` key with a DPoP proof ({{Section 5 of RFC9449}}); line breaks
are for display purposes only:

~~~ http-message
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2Iiwi...

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer
&assertion=eyJ0eXAiOiJtaXNzaW9uLWlzc3VhbmNlLWdyYW50K2p3dCIs...
&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3A
client-assertion-type%3Ajwt-bearer
&client_assertion=eyJhbGciOiJFUzI1NiIsImtpZCI6IjE2In0...
~~~

The grant is an authorization, not a client credential. A
confidential client authenticates as {{Section 3.2.1 of RFC6749}}
requires, and possession of a `cnf` key does not replace that
authentication. A public client sends `client_id` and can redeem only
a grant that carries `cnf`, since proof of possession of that key is
then the only binding of the redemption to the grant's `client_id`.

## Grant Validation {#grant-validation}

In addition to the processing {{Section 3 of RFC7523}} requires, the
consuming AS MUST validate the following and refuse the request if
any check fails:

1. the `typ` JOSE header parameter is `mission-issuance-grant+jwt`,
   checked first so that no other artifact's validation rules are
   applied to the grant ({{Section 3.11 of RFC8725}} and
   {{Section 3.12 of RFC8725}});
2. the signature, under a `kid` resolving in the published key
   material of an `iss` its local policy trusts for issuance joins;
   and the `mission` claim's `issuer` equals `iss`;
3. the `mission` claim carries `id`, a string in the Mission
   Identifier character set ({{I-D.draft-mcguinness-oauth-mission}},
   Section "Mission Identifier Format"); `expires_at`, an RFC 3339
   date-time {{RFC3339}} later than the current time; and
   `authority_hash`, in
   the form of the issuance profile's Section "Integrity Anchors",
   which the consuming AS does not recompute;
4. `aud` is a single string identical to this AS's issuer
   identifier, compared as a literal string with no normalization, so
   an array, a token endpoint URL, or another alias fails; `exp` is no
   more than 300 seconds after
   `iat`, compared exactly; `iat` is not after the current time and
   `exp` is after it, with the clock-skew leeway of
   {{Section 4.1.4 of RFC7519}} applied to these two comparisons with
   the current time only; and the `jti` has not been seen, a seen
   `jti` being retained until `exp` plus that leeway passes
   ({{single-use}});
5. the client is the grant's `client_id` ({{redemption}}): the
   authenticated client equals it, or, for a public client, the grant
   carries `cnf`; and whenever `cnf` is present, the request proves
   possession of that key, with a DPoP proof
   ({{Section 4.3 of RFC9449}}) whose public key has the `jkt`
   thumbprint or a client certificate on the TLS connection whose
   SHA-256 thumbprint matches the `x5t#S256` value, and presents no
   DPoP proof for any other key (at the PAR endpoint, no `dpop_jkt`
   other than the `jkt` value); a client certificate that only
   authenticates the client does not conflict with a `jkt` value;
6. the (`iss`, `sub`) pair maps to a local account under the
   deployment's mapping policy ({{trust}}), and every entry of the grant's
   `authorization_details` is of a type this AS supports and is one it
   serves ({{entry-types}}).

## Token Issuance {#token-issuance}

On success the consuming AS mints tokens under these rules:

- **`mission` claim.** Issued tokens carry the grant's `mission`
  object as the issuance profile's `mission` claim, unchanged except
  that they need not carry `authority_hash`; `id`, `issuer`, and
  `expires_at` always carry over ({{mission-claim}}).
- **Subset.** Issued `authorization_details` MUST be a subset of the
  grant's. The consuming AS's own policy can only narrow them: it
  MUST NOT widen, remap, or supplement them. Representing them as
  `scope` (below) is not a remapping.
- **Token response.** The token response carries the issued
  `authorization_details` as the issuance profile requires
  ({{I-D.draft-mcguinness-oauth-mission}}, Section
  "Audience and Token Response", and {{Section 7 of RFC9396}}),
  any projected `scope` beside them ({{Section 5.1 of RFC6749}}), and
  the `mission_id` and `mission_expires_at` parameters as the issuance
  profile recommends ({{I-D.draft-mcguinness-oauth-mission}}, Section
  "Binding the Mission to the Grant").
- **Scope projection.** Where a target's enforcement path consumes
  `scope`, the consuming AS also projects the issued
  `authorization_details` to `scope` as the issuance profile's Scope
  Projection rule requires ({{I-D.draft-mcguinness-oauth-mission}},
  Section "Scope Projection"), so it supports {{RFC9396}} even where
  its targets consume only `scope`.
- **Lifetime.** The consuming AS MUST NOT issue an access or refresh
  token under the grant with an expiry later than the `mission`
  object's `expires_at`. That ceiling is the Mission's expiry, not a
  liveness bound, so access tokens issued under a grant SHOULD be
  short-lived ({{security-considerations}}).
- **Key binding.** When the grant carries `cnf`, the consuming AS MUST
  bind every access token it issues under the grant, at redemption, at
  code exchange under the PAR carriage, and at each refresh, to that
  confirmation value: as a DPoP-bound access token with `token_type`
  `DPoP` ({{Section 5 of RFC9449}}) for `jkt`, or as a
  certificate-bound access token ({{Section 3 of RFC8705}}) for
  `x5t#S256`. It MUST NOT issue such a token as a bearer token or bind
  it to any other key. Refresh tokens follow the issuance profile's
  rules ({{I-D.draft-mcguinness-oauth-mission}}, Section "Refresh
  Tokens"), and every refresh still proves possession of the grant's
  `cnf` key ({{refresh}}).
- **Effective Authority Set projection.** A consuming AS with a
  Mission-state integration also applies {{effective-set-projection}}.
- **No re-approval.** The approval event already occurred at the
  Mission Issuer. The consuming AS MUST NOT prompt the Subject or
  any user for consent at redemption.

The following is an example of a successful token response:

~~~ http-message
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "access_token": "eyJ0eXAiOiJhdCtqd3QiLCJhbGciOiJFUzI1NiJ9...",
  "token_type": "DPoP",
  "expires_in": 300,
  "authorization_details": [
    {
      "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["invoices.read"],
      "constraints": {
        "resource_issued_after": "2026-07-01T00:00:00Z",
        "resource_issued_before": "2026-09-30T23:59:59Z"
      }
    }
  ],
  "mission_id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
  "mission_expires_at": "2026-12-31T23:59:59Z"
}
~~~

## Effective Authority Set Projection {#effective-set-projection}

A consuming AS with a Mission-state integration applies this section
at redemption and at every refresh.

### Mission State Source {#mission-state-source}

A consuming AS with a Mission-state integration MUST, at redemption
and at every refresh, resolve the Mission's current state and
Effective Authority Set through the Mission Status operation
({{I-D.draft-mcguinness-oauth-mission-status}}) or an equivalent
state source, and refuse when the Mission is not established
`active`. The consuming AS MUST NOT rely on an equivalent source
unless it is authenticated, is audience-scoped to the entries this AS
serves, carries the Mission's current `authorization_details` and
a monotonic state `version`, and answers within a staleness bound
the deployment publishes ({{conformance}}).

The consuming AS MUST NOT rely on a response it validated earlier,
at a later redemption or refresh, unless all of the following hold:

- it is within its reliance bound
  ({{I-D.draft-mcguinness-oauth-mission-status}}, Section "Caching")
  and within the staleness bound the deployment publishes, measured
  from the response's `iat`, whichever ends first;
- it is for the same Mission (`mission.issuer` and `mission.id`) and
  the same requested audience; and
- its `version` is not below the version the AS has retained for the
  Mission.

Where a held response meets these conditions, a transient failure of
a new request does not refuse the redemption or refresh
({{transient-failure}}).

Through the Mission Status operation, the consuming AS resolves
authority per entry audience, not for an audience of its own. For
each distinct audience the grant's entries are relevant to
({{entry-types}}; on refresh, the family ceiling's entries), it sends
one request whose `audience` is that value, unchanged (for a
`mission_resource_access` entry, its `resource` value); the Mission
Issuer authorizes each audience separately
({{I-D.draft-mcguinness-oauth-mission-status}}, Section "Request").
The consuming AS validates each response against the audience it
requested, and MUST combine only responses whose `mission.issuer`,
`mission.id`, and `mission.version` are identical. A response below
the version the AS retained for the Mission before this resolution
began is a rollback ({{transient-failure}}). Where responses within
one resolution differ in version, the AS re-queries each audience
whose response is below the highest version collected, without using
a cached response, up to a bound the deployment configures. Once all
responses report one version, the AS combines them and retains that
version; an entry relevant to several audiences survives only where
every one of their responses admits it. If it still cannot obtain
responses at one version within
the bound, the state source has failed ({{transient-failure}}). A
not-found response for an audience the grant's entries are relevant
to means the Mission is not established `active`: the AS refuses
with `invalid_grant` and carries no `mission_error` value, since a
not-found response establishes only that the AS cannot proceed, not
that the Mission terminated
({{I-D.draft-mcguinness-oauth-mission-status}}, Section "Failed
Status Checks").

Lifecycle state alone, such as an `active` state or a Status List
VALID bit, is not enough from any source, and a source that reports
only lifecycle state is not a Mission-state integration: containment
and discharge narrow an active Mission without changing its
lifecycle state, and a Status List bit carries no
`authorization_details`.

### Issued Authority {#issued-authority}

Where the Mission is `active`, the consuming AS issues the
intersection of:

1. the grant's `authorization_details`, or on refresh the family
   ceiling ({{refresh}});
2. the current Effective Authority Set;
3. the consuming AS's own policy, which narrows only
   ({{token-issuance}}); and
4. any narrower authority the client requests at the token endpoint.

Items 1 to 3 give the surviving authority. Without a narrowing
requested at the token endpoint (item 4), the AS issues the surviving
authority, which can be less than the grant's. This projection
precedes scope projection above: an AS that models authority as
`scope` maps the narrowed remainder, never the grant's original set.

An empty intersection is refused by its cause. If items 1 to 3
already intersect to nothing, the authorization itself is exhausted
and the AS refuses with `invalid_grant` ({{redemption-errors}}).
Where Containment is composed, whether the refusal carries its
`authority_contained` reason is Containment's rule
({{I-D.draft-mcguinness-oauth-mission-containment}}, Section "The
authority_contained Denial Reason"). Where that authorization
survives but a narrowing the client requested exceeds it, the
request is at fault: the refusal is `invalid_scope` where the request
carried `scope`, or `invalid_authorization_details` {{RFC9396}} where
it carried `authorization_details`. The AS MUST NOT truncate such a
request to the surviving authority.

### Transient Source Failure {#transient-failure}

A source that is unavailable, fails verification, or reports a state
`version` older than one already observed for this Mission is a
transient failure, never authority exhaustion, and is refused in a
machine-readable shape: this profile defines a token-endpoint use of
the OAuth `temporarily_unavailable` error code {{RFC6749}}
({{oauth-error-registration}}), carried with HTTP status 503. The
response MAY carry `Retry-After` per the deployment's declared
state-recovery policy. A held response that meets the conditions of
{{mission-state-source}} still satisfies the check, and the failure
then refuses nothing. For a per-audience resolution, the version
already observed is the one the AS retained before the resolution
began ({{mission-state-source}}). The consuming AS leaves the family
ceiling unchanged. On the refresh path a transient source failure
MUST NOT consume or rotate the presented refresh token, so the
client retries with the credential it already holds. `invalid_grant`
stays for the permanent failures ({{redemption-errors}}).

### Refresh {#refresh}

A refresh family's ceiling MUST NOT widen across refreshes within
the same Mission, and no token issued in the family exceeds it. The
consuming AS MUST persist the narrowed family ceiling atomically with
each successful issuance, and applies
the rollback test of {{mission-state-source}} as well: detecting a
rollback does not replace the persisted ceiling. A refresh that fails
leaves the family ceiling and the presented refresh token unchanged.
Concurrent refreshes in one family MUST NOT restore authority that an
earlier successful issuance in that family removed.

Where the grant carried `cnf`, each refresh request MUST prove
possession of that key: a DPoP proof whose public key has the `jkt`
thumbprint, or a TLS client certificate whose SHA-256 thumbprint is
the `x5t#S256` value, and present no DPoP proof for any other key. The
consuming AS refuses a refresh request that does not as
{{redemption-errors}} specifies.

## Without a Mission-State Integration {#no-state-integration}

A consuming AS without a Mission-state integration MUST NOT issue
refresh tokens under a grant, and relies instead on the grant's
`active`-at-minting gate and the short access-token lifetime
({{token-issuance}}). A consuming AS that cannot perform the
projection of {{effective-set-projection}} MUST NOT claim
containment- or discharge-aware issuance.

## Single Use {#single-use}

Consumption is atomic with issuance. The single-use `jti` check of
{{grant-validation}} refuses a grant already recorded; the record
itself is written atomically with successful issuance, after the
Mission-state check and the projection of {{effective-set-projection}}
where they apply. A redemption that fails before issuance, a transient
source failure ({{transient-failure}}) in particular, therefore
leaves the grant unconsumed and retryable, and concurrent
redemptions of one grant are resolved by that atomic record: the
loser is a replay, refused `invalid_grant`. Under the authorization
code flow carriage, PAR validation is the consuming step instead
({{par-carriage}}).

## Redemption Errors {#redemption-errors}

The consuming AS responds to a failed redemption or refresh with an
error response as defined in {{Section 5.2 of RFC6749}}. A grant that
fails any check of {{grant-validation}} is refused with the
`invalid_grant` error code ({{Section 3.1 of RFC7523}}), except as the
next sentence says of DPoP proofs, and failed client authentication
with `invalid_client`. At the PAR endpoint, at redemption, at code
exchange, and at refresh alike, a DPoP proof that fails the checks of
{{Section 4.3 of RFC9449}} is refused with `invalid_dpop_proof`, or
with `use_dpop_nonce` where the AS requires a nonce
({{Section 8 of RFC9449}}), and a request that proves no key, proves
a key other than the grant's `cnf` key, or presents a DPoP proof for
another key, with `invalid_grant`. The other refusals are:

| Condition | Response |
|---|---|
| The Mission is not `active` | `invalid_grant` |
| The authorization is exhausted ({{issued-authority}}) | `invalid_grant` |
| The requested `scope` exceeds the surviving authority | `invalid_scope` |
| The requested `authorization_details` exceeds the surviving authority | `invalid_authorization_details` |
| The state source fails ({{transient-failure}}) | `temporarily_unavailable`, HTTP 503 |

A client tells four cases apart:

- **Retry.** `temporarily_unavailable` means the authorization is
  intact and the same credential can be presented again.
  `invalid_scope` and `invalid_authorization_details` name a request
  the client can narrow and re-send under the same grant.
- **Get a fresh grant.** An expired or already redeemed grant is
  cured by a fresh one ({{minting}}). The other grant validation failures (an
  untrusted issuer, a wrong audience, an unmappable subject or
  authority) are configuration faults that a fresh grant does not
  cure, and so is a refusal after a Status not-found response.
- **Wait.** A `suspended` Mission refuses until a `resume` returns it
  to `active` ({{I-D.draft-mcguinness-oauth-mission-status}}); a fresh
  grant then cures the refusal.
- **Stop.** A `terminated` Mission, or one whose `expires_at` has
  passed, refuses for good: neither a retry nor a fresh grant cures
  the refusal.

The AS SHOULD include the issuance profile's `mission_error` member
when Mission state reports that the Mission is not `active`, so the
client can
tell Wait from Stop: `suspended` for Wait, and for Stop `revoked`,
`expired`, or `superseded` ({{I-D.draft-mcguinness-oauth-mission}},
Section "Issuance Gating") or `completed`
({{I-D.draft-mcguinness-oauth-mission-status}}). The MAS's own
refusals of a fresh grant request are in {{minting-errors}}.

# Authorization Code Flow Carriage {#par-carriage}

Deployments whose clients must traverse the authorization code flow
MAY carry the grant in a Pushed Authorization Request {{RFC9126}} as
the request parameter `mission_issuance_grant` ({{iana}}).

The AS MUST accept the `mission_issuance_grant` parameter only in a
pushed authorization request, whether sent directly or inside a
Request Object {{RFC9101}} pushed there. It MUST reject, with the
`invalid_request` error code ({{Section 4.1.2.1 of RFC6749}}), an
authorization request that carries the parameter any other way,
including in a Request Object passed to the authorization endpoint
outside PAR. The front channel then carries only `client_id` and the
`request_uri`. Direct redemption at the token endpoint
({{redemption}}) is unaffected.

The AS applies the grant validation of {{grant-validation}} at the PAR
endpoint, refusing a grant that fails it with the `invalid_grant`
error code, which {{Section 2.3 of RFC9126}} permits there, and
treats the grant as the authorization already obtained.
It MUST NOT re-prompt for consent; at most it renders the Mission
reference.

The AS consumes the grant at PAR validation: it records the `jti` as
seen there, the atomic issuance step of {{single-use}} under this
carriage, so the grant cannot be replayed into a second authorization
request. From then on the `request_uri`, and then the authorization
code, carry the authorization; a flow the user abandons, or the AS
refuses, after PAR validation leaves the grant consumed, and the
client obtains a fresh grant.

When the grant carries `cnf`, the authorization code inherits it. The
token request at code exchange MUST prove possession of that key, as
{{Section 10 of RFC9449}} binds a code to a DPoP key (for `jkt`), or
arrive over a mutual-TLS connection with that certificate (for
`x5t#S256`, {{Section 3 of RFC8705}}), and present no DPoP proof for
any other key; the AS refuses a code exchange that does not as
{{redemption-errors}} specifies.

The grant's window is not re-evaluated at code exchange, since the
authorization code carries its own lifetime. The other redemption
rules ({{token-issuance}}, {{effective-set-projection}} or
{{no-state-integration}}, and {{redemption-errors}}) apply at the
token request unchanged. A
transient source failure at code exchange refuses
`temporarily_unavailable` and MUST NOT consume the authorization code.

This carriage serves user-delegated Missions
({{I-D.draft-mcguinness-oauth-mission}}, Section "Authority Sources"),
where an authenticated resource owner exists to bind. The AS MUST
refuse the request unless the resource owner authenticated at the
authorization endpoint is the grant's Subject under the deployment's
mapping policy ({{trust}}), so the grant cannot mint tokens for
another resource owner. It refuses with the `access_denied` error
code ({{Section 4.1.2.1 of RFC6749}}), redirecting the error to the
client only where that section allows. A grant for a service-owned
or organizational
Mission has no delegating user to authenticate; it is redeemed
directly ({{redemption}}), not carried through the authorization code
flow.

# Issuance Records {#records}

The MAS MUST record each minting with the Mission record: the `jti`,
audience, requested and granted entries, any `cnf`, and time. The
consuming AS MUST record each issuance under a grant, each refresh
included, with the grant's `jti`, Mission reference, and
`authority_hash`. Only the `jti`
identifies the minting: several grants can share a Mission and an
`authority_hash`, and the single-use record ({{single-use}}) expires
with the grant's acceptance window. Together the records attribute
what was approved to the MAS and what was issued to
each consuming AS.

A deployment SHOULD reconcile MAS minting records against
consuming-AS redemption records. A deployment SHOULD treat a
redemption with no matching minting record as a security event. A
deployment states its reconciliation posture in the statement
{{conformance}} describes. A deployment operating under the
Enterprise Mission Authority Profile
({{I-D.draft-mcguinness-mission-authority-server}}) MUST reconcile
within the window its statement declares.

# Metadata {#metadata}

A MAS that issues grants publishes the following members in its
metadata ({{I-D.draft-mcguinness-mission-authority-server}}, Section
"Mission Authority Server Metadata"):

`mission_issuance_grant_endpoint`:
: REQUIRED. A string containing the URL of the MAS's Mission Issuance
  Grant endpoint ({{minting}}).

`mission_issuance_grant_endpoint_auth_methods_supported`:
: REQUIRED. A JSON array of strings naming the client-authentication
  methods the Mission Issuance Grant endpoint accepts, with the value
  space and meaning of
  `mission_submission_endpoint_auth_methods_supported`
  ({{I-D.draft-mcguinness-mission-authority-server}}).

`mission_issuance_grant_endpoint_auth_signing_alg_values_supported`:
: REQUIRED when
  `mission_issuance_grant_endpoint_auth_methods_supported` lists
  `private_key_jwt`. A JSON array of strings: the client-assertion
  algorithms this endpoint accepts, with the meaning of
  `mission_submission_endpoint_auth_signing_alg_values_supported`
  ({{I-D.draft-mcguinness-mission-authority-server}}).
{: newline="true"}

A consuming AS publishes the following members in its Authorization
Server Metadata {{RFC8414}}:

`mission_issuance_grant_supported`:
: OPTIONAL. Boolean value indicating whether the AS redeems Mission
  Issuance Grants at its token endpoint ({{redemption}}). If omitted,
  the default value is `false`.

`mission_issuance_grant_par_supported`:
: OPTIONAL. Boolean value indicating whether the AS accepts the
  `mission_issuance_grant` parameter in pushed authorization requests
  ({{par-carriage}}). If omitted, the default value is `false`.

# Relationship to Other Artifacts {#relationships}

**The cross-domain grant is this shape across a trust boundary.**
Cross-domain projection
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}) carries a
Mission to a Resource AS in another domain, under federation trust
and identity chaining. The issuance join is the same-estate case
({{trust}}), with bilateral, pre-configured trust and no identity
chaining.

**Native Mission-aware issuance replaces this grant.** An AS that
becomes natively Mission-aware implements the issuance profile and
mints without grants for its own resources. It consumes the record,
anchors, and lifecycle the MAS already operates, so nothing is
re-approved in migration.

**The Mission Join remains for other tokens.** Runtime enforcement
reads the Mission from tokens issued under this profile
(credential-carried composition,
{{I-D.draft-mcguinness-mission-runtime}}), so the Mission Join's
limit does not apply to them: the join proves a credential belongs to
the Mission's parties, never that it was issued for the Mission
({{I-D.draft-mcguinness-mission-authority-server}}, Section "Mission
Join"). The estate's other tokens are unchanged and compose through
the Mission Join; the two joins coexist per resource and per AS.

# Conformance {#conformance}

A **Mission Authority Server** implements {{minting}} in full, issues
grants exactly as {{grant}} requires, and records each minting
({{records}}).

A **consuming AS** implements {{redemption}} in full, including
{{effective-set-projection}} when it has a Mission-state integration
and {{no-state-integration}} when it has none, and records each
issuance ({{records}}). The PAR carriage of {{par-carriage}} is
OPTIONAL.

A deployment claiming this profile MUST publish a deployment
statement declaring the following. The declarations are part of its
Enforcement Scope Statement ({{I-D.draft-mcguinness-mission-runtime}},
Section "Enforcement Scope and Conformance") where it publishes one,
and stand alone otherwise; this profile does not require Runtime. The
statement declares:

- which authorization servers consume grants, and which of them have
  a Mission-state integration;
- the staleness bound of each one's state gating, and the bound on
  its Mission Status re-queries ({{mission-state-source}});
- whether each claims containment- or discharge-aware issuance
  ({{no-state-integration}}); and
- its reconciliation posture ({{records}}): the window within which
  minting and redemption records are reconciled, or that they are
  not.

A consuming AS that supports this profile publishes
`mission_issuance_grant_supported`, and one that supports the PAR
carriage publishes `mission_issuance_grant_par_supported`
({{metadata}}).

# Security Considerations {#security-considerations}

The security considerations of {{RFC7523}}, {{RFC7519}}, and
{{RFC8725}} apply. This section adds those specific to the issuance
join.

**Grant theft.** A grant authorizes issuance, so its defenses are
layered: a 300-second lifetime, a single-use `jti`, one audience,
redemption bound to the Mission's `client_id`, and `cnf` key binding
whenever the grant request is sender-constrained. A stolen grant is
useless to any party that cannot also
authenticate as the recorded client, or prove possession of the `cnf`
key, at the named AS within that window. Deployments whose client
credentials are weak SHOULD require `cnf` (DPoP {{RFC9449}} or mutual
TLS {{RFC8705}}).

**Mission Issuer compromise reaches issuance.** In a MAS-only
deployment, MAS compromise corrupts records and state. Under this
profile a compromised MAS also mints grants every consuming AS
honors, so compromise reaches token issuance across the estate. The
consuming authorization servers' redemption records ({{records}})
are the independent record that bounds and exposes such minting; at
estate scale, reconciling them against the MAS's minting records is
the only check on this compromise class.

**Externally derived authority.** The consuming AS issues authority
derived elsewhere. The grant bounds its exposure: it issues only
within the grant's `authorization_details`, only to the grant's
client, and never past the Mission's `expires_at`
({{token-issuance}}). Its own policy can narrow further or refuse a
grant outright; nothing obliges issuance.

**Type confusion.** Three issuer-signed JWT artifacts describe
Missions: the Mission Mandate
({{I-D.draft-mcguinness-mission-mandate}}, evidence), the
cross-domain grant (foreign domain), and this grant (same estate).
Explicit typing with mutually
exclusive validation rules ({{Section 3.11 of RFC8725}} and
{{Section 3.12 of RFC8725}}) is the defense: every consumer checks
`typ` first, and none accepts another's type.

**Revocation latency.** New grants stop at the MAS `active` gate when
the state change commits. A grant already minted can still be
redeemed within its 300 seconds at a consuming AS without a
Mission-state integration. The residual there is the grant's
remaining lifetime and clock-skew leeway ({{grant-validation}}), plus
the issued token's lifetime, plus that of each further exchange that
checks no Mission state, capped by `expires_at`. Under the PAR
carriage the grant is consumed at PAR validation, and the sum then
runs through the pending authorization request, bounded by the
`request_uri` lifetime ({{Section 2.2 of RFC9126}}) and any
resource-owner interaction timeout, and through the authorization
code's lifetime, before the issued token's; `expires_at` still caps
it. Hence the short-lifetime recommendation ({{token-issuance}}). In
either mode,
issued access tokens run to their own expiry. With a Mission-state
integration, an outstanding refresh token is refused at its next
use, and a refresh re-projects through the Effective Authority Set
({{effective-set-projection}}), so a Mission contained or discharged
between issuance and refresh does not renew its original, narrowed
authority, within the staleness bound the deployment publishes
({{conformance}}). Where the runtime layer is deployed, the Policy
Decision Point's re-check bounds outstanding-token use independently.

**Consent integrity.** The approval the grant rests on was rendered
and committed at the Mission Issuer under the issuance profile's
rules. The consuming AS relies on that approval and does not
substitute one of its own: its non-prompting duty
({{token-issuance}}, {{par-carriage}}) prevents consent-surface
confusion where the Subject holds accounts at both.

# Privacy Considerations {#privacy-considerations}

The grant carries the Mission reference, the Subject's `sub`, the
`client_id`, and an authority subset to the consuming AS, which may
be operated by a different organizational unit than the MAS.
Minimization is structural: the MAS scopes `authorization_details`
to what the audience serves ({{minting}}), and nothing else of the
record (no `purpose` text, no Intent, no full Authority Set) travels.
The Mission identifier is a correlator across MAS and AS logs by
design; that correlation is the audit trail, and the issuance
profile provides no cross-audience unlinkability
({{I-D.draft-mcguinness-oauth-mission}}, Section "Mission Identifier
Correlation").

# IANA Considerations {#iana}

## Media Type Registration

IANA is requested to register one media type per {{RFC6838}}.

### application/mission-issuance-grant+jwt

- Type name: application
- Subtype name: mission-issuance-grant+jwt
- Required parameters: none
- Optional parameters: none
- Encoding considerations: binary; a Mission Issuance Grant is a JWT;
  JWT values are encoded as a series of base64url-encoded values (some
  of which may be the empty string) separated by period ('.')
  characters
- Security considerations: see {{security-considerations}}
- Interoperability considerations: see this document
- Published specification: this document
- Applications that use this media type: Mission Authority Servers
  and OAuth authorization servers implementing this profile
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
{{I-D.draft-mcguinness-mission-authority-server}}:

- Metadata Name: `mission_issuance_grant_endpoint`
- Metadata Description: URL of the MAS's Mission Issuance Grant
  endpoint
- Change Controller: IETF
- Specification Document(s): {{metadata}} of this document

- Metadata Name: `mission_issuance_grant_endpoint_auth_methods_supported`
- Metadata Description: Client-authentication methods the Mission
  Issuance Grant endpoint accepts
- Change Controller: IETF
- Specification Document(s): {{metadata}} of this document

- Metadata Name:
  `mission_issuance_grant_endpoint_auth_signing_alg_values_supported`
- Metadata Description: Client-assertion signing algorithms the
  Mission Issuance Grant endpoint accepts
- Change Controller: IETF
- Specification Document(s): {{metadata}} of this document

## OAuth Authorization Request Parameter Registration

IANA is requested to register the following in the "OAuth Parameters"
registry {{RFC6749}}, for the parameter carried in Pushed Authorization
Requests ({{par-carriage}}):

- Parameter name: `mission_issuance_grant`
- Parameter usage location: authorization request
- Change controller: IETF
- Specification document(s): {{par-carriage}} of this document

## OAuth Extensions Error Registration {#oauth-error-registration}

IANA is requested to register the following in the "OAuth Extensions
Error" registry {{RFC6749}}. The name is the existing OAuth error code
of {{Section 4.1.2.1 of RFC6749}}, registered only for the
authorization endpoint; this entry adds its token-endpoint use
({{transient-failure}}), as {{RFC8628}} did for `access_denied`.

- Name: `temporarily_unavailable`
- Usage Location: token error response
- Protocol Extension: Mission Issuance Grant
- Change Controller: IETF
- Specification Document(s): {{transient-failure}} of this document

## OAuth Authorization Server Metadata Registration

IANA is requested to register the following in the "OAuth Authorization
Server Metadata" registry {{RFC8414}}:

- Metadata Name: `mission_issuance_grant_supported`
- Metadata Description: Whether the authorization server redeems
  Mission Issuance Grants at its token endpoint
- Change Controller: IETF
- Specification Document(s): {{metadata}} of this document

- Metadata Name: `mission_issuance_grant_par_supported`
- Metadata Description: Whether the authorization server accepts the
  Mission Issuance Grant parameter in Pushed Authorization Requests
- Change Controller: IETF
- Specification Document(s): {{metadata}} of this document

--- back

# Document History {#document-history}

\[\[ To be removed from the final specification ]]

- Normative follow-ups to the tightening pass (D685). The grant
  admits any supported authorization-details type under that type's
  semantics and fails closed on an unsupported transformation. Its
  `sub` is an injective MAS-local mapping of the recorded Subject, and
  its `aud` is the consuming AS's issuer identifier only. Grant
  Validation checks the required `mission` members. The grant
  endpoint carries client assertions in JSON, advertises its
  authentication methods, defines its own error codes, and always
  binds a verified sender constraint into `cnf`; a `cnf` grant yields
  key-bound access tokens through code exchange and refresh. A
  requested narrowing that exceeds the surviving authority is
  refused, not truncated. The refresh family and its ceiling are
  defined, and the ceiling is persisted at every issuance. A Status
  not-found refusal carries no `mission_error`, and reliance on a
  cached Status response is bounded. PAR errors are named, the
  causal-attribution rule for `authority_contained` moves to
  Containment, the scope statement moves to Trust, and a deployment
  statement is required.
- Tightened throughout with no requirement change. Each rule has one
  home: the `cnf` possession check is in Grant Validation, the `jti`
  record in Single Use, the `typ` refusal in Grant Validation, the
  per-resource version rule in Mission State Source, and the MAS's
  refusal notes in Grant Errors. Single Use and Without a
  Mission-State Integration are Redemption subsections, Issued Tokens
  folds into Relationship to Other Artifacts, Composite Provision is
  removed (Architecture and the MAS draft state its positioning), and
  a new Issuance Records section holds minting records, redemption
  records, and reconciliation, including the Enterprise
  reconciliation requirement that Security Considerations carried.
  Restatements of the issuance profile's Scope Projection, the MAS
  error object, and Derivation Limits' counting rule are pointers.
  The equivalent-source properties bind the consuming AS. The Mission
  Authority Server Metadata registration uses that registry's
  template fields. The Substrate, Architecture, and Consent Evidence
  references are removed.
- Redemption Errors separates a `suspended` Mission, which a `resume`
  restores and a fresh grant then cures, from a `terminated` one,
  which neither a retry nor a fresh grant cures. The `mission_error`
  values follow the lifecycle migration and include `suspended` and
  `completed`, and `mission_not_active` at the MAS is no longer called
  an unconditional signal to stop. No requirement changes.

# Acknowledgments
{:numbered="false"}

The author thanks the implementers and reviewers of the Mission-Bound
Authorization work for feedback that shaped this profile.
