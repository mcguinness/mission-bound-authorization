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
  RFC8628:
  RFC8725:
  I-D.draft-mcguinness-oauth-mission-consent-evidence:
    title: "Mission Consent Evidence for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-consent-evidence.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
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

This specification defines the Mission Issuance Grant, a profile of
the JSON Web Token (JWT) authorization grant of RFC 7523. A Mission
Authority Server approves and records Missions without changing an
estate's OAuth Authorization Servers. Under this profile it also
issues, for an active Mission, a short-lived, audience-restricted,
single-use JWT that the client presents at an Authorization Server's
token endpoint. The Authorization Server validates the grant and
issues Mission-bound tokens: they carry the Mission, are bounded by
the authority the grant conveys, and expire no later than the
Mission. An Authorization Server that checks Mission state at
redemption and at every refresh stops issuing and renewing those
tokens once the Mission is no longer active, and narrows them when
its authority is narrowed; one that does not check issues no refresh
tokens. Approval,
the Mission record, and its lifecycle stay at the Mission Authority
Server.

--- middle

# Introduction

Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} (the "issuance profile") binds
issued authority to a durable, human-approved Mission, with the
Authorization Server (AS) as the Mission Issuer. The Mission Authority
Server (MAS, {{I-D.draft-mcguinness-mission-authority-server}}) hosts
the same Mission without changing the estate's Authorization Servers:
it validates Mission Intents, runs approval, records Missions, and
operates their lifecycle. The tokens those Authorization Servers issue
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

Every grant is issued against current Mission state, so a revoked
Mission receives no new grants. An AS with a Mission-state
integration ({{conventions}}) also checks the Mission at redemption
and at every refresh; one without issues no refresh tokens, so its
tokens end with their own short lifetime. Either way, every path to
new tokens passes a Mission-state check: the issuance-gate kill switch
that a MAS alone does not provide
({{I-D.draft-mcguinness-mission-authority-server}}).

The AS implements none of the issuance profile's intake, approval
ceremony, authority derivation, record, or lifecycle surfaces; those
stay at the MAS. A deployment can adopt the issuance join at some
Authorization Servers and keep the Mission Join at others
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
  carried by a grant that an Authorization Server redeems at its
  token endpoint.

Mission Issuance Grant (grant):
: The signed assertion of {{grant}}, issued by the MAS and redeemed
  for Mission-bound tokens.

Consuming Authorization Server (consuming AS):
: An OAuth Authorization Server {{RFC6749}} that redeems Mission
  Issuance Grants at its token endpoint; conformance role of
  {{conformance}}.

Mission-state integration:
: A consuming AS's means of resolving the Mission's current state and
  Effective Authority Set at redemption and at every refresh
  ({{mission-state-source}}). A consuming AS either has one and
  applies {{effective-set-projection}}, or has none and issues no
  refresh tokens under a grant ({{no-state-integration}}).

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
    |                         |<-- (D) Mission Status -------|
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
    Mission's current state and Effective Authority Set
    ({{effective-set-projection}}).

(E) The consuming AS issues Mission-bound tokens within the grant's
    authority and that set ({{token-issuance}}).

(F) Each refresh repeats (D) before (E). A consuming AS without a
    Mission-state integration skips (D) and issues no refresh token
    ({{no-state-integration}}).

## Trust {#trust}

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

The duties divide as follows. The MAS holds the approval event,
the record and its anchors, the lifecycle, and grant minting. The
consuming AS holds client authentication, token minting bounded by
the grant, refresh, and its ordinary token-plane obligations. An
auditor attributes what was approved to the MAS record and what was
issued to the consuming AS's log, joined by the Mission reference
the grant carries.

## Issued Tokens {#issued-tokens}

Tokens issued under this profile are Mission-bound: they carry the
`mission` claim, their authority is a subset of the consented
Authority Set, and their issuance is gated on Mission state, at grant
issuance always and at redemption and every refresh where the
consuming AS has a Mission-state integration.

Runtime enforcement reads the Mission from these tokens
(credential-carried composition,
{{I-D.draft-mcguinness-mission-runtime}}), so the Mission Join's
limit does not apply to them: the join proves a credential belongs to
the Mission's parties, never that it was issued for the Mission
({{I-D.draft-mcguinness-mission-authority-server}}, Section "Mission
Join"). Tokens the estate issues outside this profile are unchanged
and continue to compose through the Mission Join.

# The Mission Issuance Grant {#grant}

A Mission Issuance Grant is a JWT {{RFC7519}} signed as a JWS
{{RFC7515}} by the Mission Issuer. Its JOSE header MUST carry the
`typ` header parameter with the value `mission-issuance-grant+jwt`
({{iana}}), `alg`, and a `kid` that
resolves in the Mission Issuer's published key material. A JWT with
any other `typ`, a Mission Mandate
({{I-D.draft-mcguinness-mission-mandate}}) in particular, is not a
Mission Issuance Grant and is refused at redemption
({{grant-validation}}).

Claims:

`iss`:
: REQUIRED. The Mission's `issuer`: the MAS issuer URL.

`sub`:
: REQUIRED. The Mission's recorded Subject identifier
  (`subject.sub`), interpreted at the consuming AS under the
  deployment's mapping policy ({{trust}}).

`aud`:
: REQUIRED. The consuming AS's issuer identifier
  ({{grant-validation}}).

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
: REQUIRED. The `mission_resource_access` entries {{RFC9396}} the
  consuming AS issues against: a subset of the Mission's Effective
  Authority Set, scoped to the resources this AS serves
  ({{minting-rules}}).

`cnf`:
: OPTIONAL. A confirmation claim {{RFC7800}} binding redemption to a
  key: the `jkt` member for OAuth 2.0 Demonstrating Proof of
  Possession (DPoP, {{Section 6.1 of RFC9449}}), or the `x5t#S256`
  member for mutual TLS ({{Section 3.1 of RFC8705}}), set by the MAS
  only from a sender constraint it verified on the grant request
  ({{minting-rules}}). When it is
  present, the consuming AS MUST require proof of possession of that
  key at redemption: a DPoP proof in the token request whose public
  key has the `jkt` thumbprint, or a client certificate on the TLS
  connection whose SHA-256 thumbprint matches the `x5t#S256` value.

The following is an example of a decoded grant payload; the
`authority_hash` value is illustrative:

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
      "constraints": {
        "resource_issued_after": "2026-07-01T00:00:00Z"
      }
    }
  ]
}
~~~

## The `mission` Claim {#mission-claim}

The grant's `mission` claim is the issuance profile's `mission` claim
object, whose `id` and `issuer` members the issuance profile defines
({{I-D.draft-mcguinness-oauth-mission}}, Section "The Mission Claim").
This profile requires two further members:

- **`expires_at`.** The issuance profile defines `expires_at` as a
  REQUIRED Mission Record member and an OPTIONAL member of the
  `mission` claim it mirrors. This profile elevates the claim mirror
  to REQUIRED for the credentials it governs. The Lifetime rule
  ({{token-issuance}}) depends on that elevation: it caps every token
  issued under the grant at the `mission` object's `expires_at`.
- **`authority_hash`.** The `mission` object MUST carry
  `authority_hash` ({{I-D.draft-mcguinness-oauth-mission}}, Section
  "Integrity Anchors"), reintroducing it beyond the issuance profile's
  baseline claim as this profile's lineage anchor: it names the
  approved Authority Set the grant derives from, for a consuming AS
  that, without a Mission-state integration, has no further channel
  back to the Mission Issuer once it holds the grant. The consuming
  AS carries it unchanged ({{token-issuance}}) and does not verify it.

# Obtaining a Grant {#minting}

A MAS implementing this profile serves a Mission Issuance Grant
endpoint, published as `mission_issuance_grant_endpoint` in its
metadata ({{metadata}}).

## Grant Request {#minting-request}

The requester POSTs an `application/json` object to the endpoint over
TLS, authenticated as {{minting-rules}} requires:

`mission_id`:
: REQUIRED. A string. The Mission the grant is minted for; its
  `issuer` is this MAS.

`audience`:
: REQUIRED. A string. The consuming AS the grant is for, becoming the
  grant's `aud`. The MAS mints only for audiences its configuration
  names ({{trust}}).

`authorization_details`:
: OPTIONAL. An array. A narrower subset the requester asks the grant
  to carry, under the issuance profile's subset rule. If it is
  omitted, the MAS scopes the grant to the entries the named audience
  serves ({{minting-rules}}); if it is present, it MUST NOT widen
  beyond that scope.

The following is an example of a grant request:

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
      "actions": ["read"],
      "constraints": {
        "resource_issued_after": "2026-07-01T00:00:00Z"
      }
    }
  ]
}
~~~

## Grant Processing {#minting-rules}

The MAS MUST apply the following rules:

1. **Requester.** The MAS authenticates the requester as its Mission
   submission endpoint does
   ({{I-D.draft-mcguinness-mission-authority-server}}, Section
   "Mission Submission"). The requester MUST be the Mission's
   recorded client. Any other caller, including a delegate or
   enforcement point that the Mission Join Assertion endpoint admits,
   receives `not_found`, which preserves the MAS's anti-oracle
   property.
2. **State gate.** A grant is minted only while the Mission is
   `active`, established from the MAS's own record at minting. In any
   other state the MAS refuses.
3. **Subset and audience.** The grant's `authorization_details` MUST
   be a subset, under the issuance profile's subset rule
   ({{I-D.draft-mcguinness-oauth-mission}}, Section "Subset Rule"), of
   the Mission's current Effective Authority Set
   ({{I-D.draft-mcguinness-oauth-mission-status}}). That is the
   consented Authority Set less what any composed narrowing companion
   has removed; a grant is a derivation, so a contained capability is
   absent from it ({{I-D.draft-mcguinness-oauth-mission-containment}},
   Section "Derivation Gating"). The grant SHOULD carry only the
   entries the named consuming AS serves. The requester MAY request a
   narrower subset. The MAS MUST refuse a request for a wider one.
4. **Derivation event.** Each grant minted is a derivation event.
   Where the Mission's established `derivation_limit`
   ({{I-D.draft-mcguinness-oauth-mission-derivation-limits}}) is set, the MAS MUST count
   grants against it atomically and refuse beyond
   it, which gives that ceiling a binding locus under the standalone
   binding. A grant counts when its minting commits. Redemption and
   refresh at a consuming AS do not increment this counter, so the
   limit bounds the grants the MAS issues, not the number of tokens
   consuming Authorization Servers issue from them
   ({{I-D.draft-mcguinness-oauth-mission-derivation-limits}}, Section
   "Mission Issuance Grant Minting").
5. **Key binding.** When the MAS includes `cnf`, it MUST take the key
   from a sender constraint it verified on the grant request: the
   public key of the request's DPoP proof, as `jkt`, or the client
   certificate of the mutual-TLS connection, as `x5t#S256`. A
   private-key-JWT client assertion's signing key authenticates the
   client and MUST NOT become `cnf`. A grant request with no verified
   sender constraint yields a grant without `cnf`. The redemption
   rules for client authentication and public clients
   ({{redemption}}) apply unchanged, so a public client cannot redeem
   such a grant.
6. **Evidence.** Each minting is recorded with the Mission record:
   the `jti`, audience, requested and granted entries, and time.

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
({{I-D.draft-mcguinness-mission-authority-server}}): a JSON body with a
REQUIRED `error` string and an OPTIONAL `error_description`. This
endpoint uses:

| `error` | HTTP | Condition |
|---|---|---|
| `invalid_request` | 400 | Missing or malformed `mission_id` or `audience`, or an unparseable body |
| `unauthorized` | 401 | Request not authenticated |
| `not_found` | 404 | Unknown `mission_id`, or the requester is not the Mission's recorded client |
| `invalid_audience` | 400 | `audience` names no AS this MAS issues grants for |
| `mission_not_active` | 409 | The Mission is not `active` |
| `invalid_authorization_details` | 400 | The request is wider than the Effective Authority Set or the audience's scope |
| `derivations_exhausted` | 409 | The Mission's `derivation_limit` is reached |

`derivations_exhausted` is the condition the `mission_error` value of
that name reports at a token endpoint
({{I-D.draft-mcguinness-oauth-mission-derivation-limits}}).
`not_found` covers both an unknown Mission and a requester that is not
the recorded client, so the split never becomes a membership oracle;
`invalid_audience`, `mission_not_active`,
`invalid_authorization_details`, and `derivations_exhausted` are
returned only to the authenticated recorded client, to which Mission
state is already visible.

# Redemption {#redemption}

The client presents the grant to the consuming AS's token endpoint
as a JWT authorization grant {{RFC7523}}. The following example shows
a confidential client that authenticates with a JWT
({{Section 2.2 of RFC7523}}); line breaks are for display purposes
only:

~~~ http-message
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer
&assertion=eyJ0eXAiOiJtaXNzaW9uLWlzc3VhbmNlLWdyYW50K2p3dCIs...
&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3A
client-assertion-type%3Ajwt-bearer
&client_assertion=eyJhbGciOiJFUzI1NiIsImtpZCI6IjE2In0...
~~~

The grant is an authorization, not a client credential: the client
still proves it is the grant's `client_id`. A confidential client
authenticates to this AS as {{Section 3.2.1 of RFC6749}} requires, and
possession of a `cnf` key does not replace that authentication. A
public client, which cannot authenticate, sends `client_id` in the
request and can redeem only a grant that carries `cnf`: proof of
possession of that key binds the redemption to the grant's
`client_id`, and without `cnf` nothing does.

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
3. `aud` names this AS; `exp` is no more than 300 seconds after
   `iat`, compared exactly; `iat` is not after the current time and
   `exp` is after it, with the clock-skew leeway of
   {{Section 4.1.4 of RFC7519}} applied to these two comparisons with
   the current time only; and the `jti` has not been seen. The record
   of a seen `jti` is written atomically with successful issuance and
   retained until `exp` plus that leeway passes ({{single-use}});
4. the client is the grant's `client_id` ({{redemption}}): the
   authenticated client equals it, or, for a public client, the grant
   carries `cnf`; and whenever `cnf` is present, the request proves
   possession of that key ({{grant}});
5. `sub` maps to a local account under the deployment's mapping
   policy ({{trust}}), and the grant's `authorization_details`
   map to resources this AS serves.

## Token Issuance {#token-issuance}

On success the consuming AS mints tokens under these rules:

- **Verbatim `mission` claim.** Issued tokens carry the grant's
  `mission` object verbatim as the issuance profile's `mission` claim, including
  the `expires_at` member ({{mission-claim}}).
- **Subset.** Issued `authorization_details` MUST be a subset of the
  grant's. The consuming AS's own policy can only narrow them: it
  MUST NOT widen, remap, or supplement them. Representing them as
  `scope` (below) is not a remapping.
- **Token response.** The token response carries the issued
  `authorization_details` as the issuance profile requires for
  Mission-bound issuance ({{I-D.draft-mcguinness-oauth-mission}},
  Section "Mission-Bound Access Tokens", and {{Section 7 of RFC9396}}),
  any projected `scope` beside them ({{Section 5.1 of RFC6749}}), and
  the `mission_id` and `mission_expires_at` parameters as the issuance
  profile recommends ({{I-D.draft-mcguinness-oauth-mission}}, Section
  "Binding the Mission to the Grant").
- **Scope projection.** Where a target's enforcement path consumes
  `scope`, the consuming AS also projects the issued
  `authorization_details` to `scope` under the issuance profile's
  scope-projection rule ({{I-D.draft-mcguinness-oauth-mission}},
  Section "Scope Projection"): every issued scope value corresponds
  to authority the grant conveys, and none conveys authority, or
  relaxes a constraint, that the grant does not. The consuming AS
  therefore supports {{RFC9396}} even where its targets consume only
  `scope`.
- **Lifetime.** The consuming AS MUST NOT issue an access or refresh
  token under the grant with an expiry later than the `mission`
  object's `expires_at`. That ceiling is the Mission horizon, not a
  liveness bound, so access tokens issued under a grant SHOULD be
  short-lived: absent a redemption-time state check, an issued access
  token's own lifetime is the window in which a revoked Mission's
  token keeps working at the token layer.
- **Effective Authority Set projection.** A consuming AS with a
  Mission-state integration gates redemption and every refresh on
  current Mission state and projects the issued authority through the
  Mission's current Effective Authority Set
  ({{effective-set-projection}}).
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
  "token_type": "Bearer",
  "expires_in": 300,
  "authorization_details": [
    {
      "type": "mission_resource_access",
      "resource": "https://api.example.com/invoices",
      "actions": ["read"],
      "constraints": {
        "resource_issued_after": "2026-07-01T00:00:00Z"
      }
    }
  ],
  "mission_id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
  "mission_expires_at": "2026-12-31T23:59:59Z"
}
~~~

A grant redeems exactly once ({{single-use}}). Later token needs are
met by the issued refresh token (state-gated) or a fresh grant
(state-gated at minting), so every path to new authority re-enters a
Mission-state gate.

## Effective Authority Set Projection {#effective-set-projection}

A consuming AS with a Mission-state integration applies this section
at redemption and at every refresh. {{single-use}} applies to every
consuming AS, and {{no-state-integration}} states what applies to one
without an integration.

### Mission State Source {#mission-state-source}

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

Through the Mission Status operation, the consuming AS resolves
authority per resource, not for an audience of its own. It sends one
request for each distinct resource audience that the grant's
`authorization_details` (on refresh, the refresh family's ceiling)
name, naming that audience in the request's `audience`; the Mission
Issuer authorizes it separately for each audience it requests
({{I-D.draft-mcguinness-oauth-mission-status}}, Section "Request").
The consuming AS validates each response against the audience it
requested, and MUST combine only responses whose `mission.issuer`,
`mission.id`, and `mission.version` are identical. When the versions
differ, it re-queries, up to a bound the deployment configures. If it
still cannot obtain responses at one version, the state source has
failed ({{transient-failure}}): the AS refuses with
`temporarily_unavailable`, and the grant stays unconsumed
({{single-use}}). Each response is authenticated, scoped to the
requested audience, and carries current `authorization_details` and
the Mission's state `version`.

Lifecycle state alone, such as an `active` state or a Status List
VALID bit, is not enough from any source: containment and discharge
narrow an active Mission without changing its lifecycle state, and a
Status List bit carries no `authorization_details`.

### Issued Authority {#issued-authority}

Where the Mission is `active`, the consuming AS issues the
intersection of:

1. the grant's `authorization_details`, or on refresh the refresh
   family's own ceiling ({{refresh}});
2. the current Effective Authority Set;
3. the consuming AS's own policy, which narrows only, per the subset
   rule above; and
4. any narrower authority the client requests at the token endpoint.

A partial intersection issues only the remainder. This
projection precedes scope projection above: an AS that models
authority as `scope` maps the narrowed remainder, never the grant's
original set.

An empty intersection is refused by its cause. If items 1 to 3
already intersect to nothing, the authorization itself is exhausted
and the AS refuses with `invalid_grant` ({{redemption-errors}}). The
refusal MAY carry the `authority_contained` value in the
`mission_denial_reason` member where Containment causally removed the
authority, and a collapse from any other cause MUST NOT be reported
as containment merely because Containment is composed
({{I-D.draft-mcguinness-oauth-mission-containment}}, Section "The
authority_contained Denial Reason"). Where that authorization
survives and only the narrowing the client requested fails to
intersect it, the request is at fault: the refusal is `invalid_scope`
where the request carried `scope`, or `invalid_authorization_details`
{{RFC9396}} where it carried `authorization_details`.

### Transient Source Failure {#transient-failure}

A source that is unavailable, fails verification, or reports a state
`version` older than one already observed for this Mission is a
transient failure, never authority exhaustion, and is refused in a
machine-readable shape: this profile defines a token-endpoint use of
the OAuth `temporarily_unavailable` error code {{RFC6749}}
({{oauth-error-registration}}), carried with HTTP status 503. The
response MAY carry `Retry-After` per the
deployment's declared state-recovery policy.
The consuming AS leaves its stored ceiling unchanged. `invalid_grant`
stays for the permanent classes: an invalid, expired, or replayed
grant, a Mission that is not established `active`, and a genuinely
empty current intersection.

### Single Use {#single-use}

Consumption is atomic with issuance. The single-use `jti` check of
{{grant-validation}} refuses a grant already recorded; the record itself is
written atomically with successful issuance, after the state gate and
this projection. A redemption that fails before issuance, a transient
source failure in particular, therefore leaves the grant unconsumed
and retryable, and concurrent redemptions of one grant are resolved by
that atomic record: the loser is a replay, refused `invalid_grant`. On
the refresh path a transient source failure MUST NOT consume or rotate
the presented refresh token, so the client retries with the credential
it already holds. Under the authorization code flow carriage, PAR
validation is the consuming step instead ({{par-carriage}}).

### Refresh {#refresh}

A refresh family's issued authority MUST NOT widen across refreshes
within the same Mission: the consuming AS atomically narrows its own
stored ceiling on every refresh, or retains the highest Mission state
`version` it has observed and rejects a source reporting a lower one
as a rollback.

### Without a Mission-State Integration {#no-state-integration}

A consuming AS without a Mission-state integration MUST NOT issue
refresh tokens under a grant, and relies instead on the grant's
`active`-at-minting gate and the short access-token lifetime above. A
source that reports lifecycle state alone is not a Mission-state
integration under this profile ({{mission-state-source}}). A consuming
AS that cannot perform this projection MUST NOT claim containment- or
discharge-aware issuance.

## Redemption Errors {#redemption-errors}

The consuming AS responds to a failed redemption or refresh with an
error response as defined in {{Section 5.2 of RFC6749}}. A grant that
fails any check of {{grant-validation}} is refused with the
`invalid_grant` error code ({{Section 3.1 of RFC7523}}), and failed
client authentication with `invalid_client`. The other refusals are:

| Condition | Response |
|---|---|
| The Mission is not `active` | `invalid_grant` |
| The authorization is exhausted ({{issued-authority}}) | `invalid_grant` |
| The requested `scope` does not intersect the surviving authority | `invalid_scope` |
| The requested `authorization_details` does not intersect the surviving authority | `invalid_authorization_details` |
| The state source fails ({{transient-failure}}) | `temporarily_unavailable`, HTTP 503 |

A client tells three cases apart:

- **Retry.** `temporarily_unavailable` with HTTP 503 means the
  authorization is intact and the same credential can be presented
  again, without parsing `error_description`. `invalid_scope` and
  `invalid_authorization_details` name a request the client can
  narrow and re-send under the same grant.
- **Get a fresh grant.** An expired or already redeemed grant is
  cured by obtaining a fresh one ({{minting}}). The other grant
  validation failures (an untrusted issuer, a wrong audience, an
  unmappable subject or authority) are configuration faults that a
  fresh grant does not cure.
- **Stop.** While the Mission stays out of the `active` state,
  neither a retry nor a fresh grant cures the refusal. The AS SHOULD
  include the issuance profile's `mission_error` member
  (`mission_revoked`, `mission_expired`, or `mission_superseded`;
  {{I-D.draft-mcguinness-oauth-mission}}, Section "Issuance Gating").
  A client that requests a fresh grant is refused at the MAS with
  `mission_not_active` ({{minting-errors}}), the authoritative signal
  to stop.

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
outside PAR. The front channel then carries only the `request_uri`.
This restriction concerns the authorization-request parameter; direct
redemption at the token endpoint ({{redemption}}) is unaffected.

The AS applies the grant validation of {{grant-validation}} at the PAR
endpoint and treats the grant as the authorization already obtained.
It MUST NOT re-prompt for consent; at most it renders the Mission
reference.

The AS consumes the grant at PAR validation: the 300-second `exp`,
`iat`, and `aud` checks and the single-use `jti` check are evaluated
there, and the `jti` is recorded as seen at that point, so the grant
cannot be replayed into a second authorization request. Recording
there is the atomic issuance step of {{single-use}} under this
carriage: from that point the `request_uri`, and then the
authorization code, carry the authorization. A flow the user abandons,
or the AS refuses, after PAR validation therefore leaves the grant
consumed, and the client obtains a fresh grant.

The grant's window is not re-evaluated at code exchange; the issued
authorization code carries its own lifetime from there. All
remaining redemption rules (subset, lifetime, Effective Authority Set
projection, no re-approval, and the error mapping of
{{redemption-errors}}) apply at the token request unchanged. A
transient source failure at code exchange refuses
`temporarily_unavailable` and MUST NOT consume the authorization code,
so the exchange stays retryable within the code's own lifetime.

This carriage serves user-delegated Missions
({{I-D.draft-mcguinness-oauth-mission}}, Section "Authority Sources"),
where an authenticated resource owner exists to bind. The AS MUST
bind the resource owner
authenticated at the authorization endpoint to the grant's `sub`: it
proceeds only where the authenticated user is the grant's Subject
under the deployment's mapping policy ({{trust}}). The AS
MUST refuse when a different user authenticates, so the grant cannot
mint tokens for the wrong resource owner.

For a service-owned or organizational Mission there is no delegating
user to authenticate; such a grant is redeemed directly
({{redemption}}), not carried through the authorization code flow.
The client MUST still be the grant's `client_id`
({{grant-validation}}).

# Metadata {#metadata}

A MAS that issues grants publishes the following member in its
metadata ({{I-D.draft-mcguinness-mission-authority-server}}, Section
"Mission Authority Server Metadata"):

`mission_issuance_grant_endpoint`:
: URL of the MAS's Mission Issuance Grant endpoint ({{minting}}).

A consuming AS publishes the following members in its Authorization
Server Metadata {{RFC8414}}:

`mission_issuance_grant_supported`:
: OPTIONAL. Boolean value; `true` when the AS redeems Mission Issuance
  Grants at its token endpoint ({{redemption}}). If omitted, the
  default value is `false`.

`mission_issuance_grant_par_supported`:
: OPTIONAL. Boolean value; `true` when the AS accepts the
  `mission_issuance_grant` parameter in Pushed Authorization Requests
  ({{par-carriage}}). If omitted, the default value is `false`.

# Relationship to Other Artifacts {#relationships}

**The Mandate is evidence; this grant authorizes.** Both are
issuer-signed statements about a Mission, and their `typ` values keep
them apart: the token endpoint refuses a Mandate
({{grant-validation}}), and a Mandate verifier refuses a grant
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

**Native Mission-aware issuance replaces this grant.** An AS that
becomes natively Mission-aware implements the issuance profile and
mints without grants for its own resources; the record, anchors, and
lifecycle it
consumes are the same ones the MAS already operates, so nothing is
re-approved in migration. Until then, the issuance join gives the
estate Mission-bound tokens without the issuance profile's intake,
approval, and record surfaces at each AS.

**The Mission Join remains for everything else.** Tokens minted
under this profile compose credential-carried at the Policy Decision
Point (PDP); ordinary tokens continue to compose through the Mission
Join. The two joins coexist per resource and per AS.

## Composite Provision {#composite}

In the substrate's terms ({{I-D.draft-mcguinness-mission-substrate}})
the MAS alone claims neither Credential-Bound nor Lifecycle-Gated
Authorization for the tokens its unchanged Authorization Servers
issue. A MAS composed with its consuming Authorization Servers under
this profile supplies both capabilities, jointly, for the resources
those ASs serve. In the Mission Assurance Levels
({{I-D.draft-mcguinness-mission-architecture}}), this profile makes
Baseline Issuance reachable under the standalone binding, and a
consuming AS's refresh gating adds the state-aware half-step.

# Conformance {#conformance}

**Mission Authority Server** implements {{minting}} in full:

- the authenticated endpoint, answering any caller other than the
  recorded client with `not_found`;
- the `active`-only gate;
- subset and audience scoping;
- derivation counting where a `derivation_limit` is set;
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
  consuming AS that issues refresh tokens ({{effective-set-projection}});
- no refresh tokens without a Mission-state integration
  ({{no-state-integration}});
- no re-approval; and
- the redemption error mapping of {{redemption-errors}}.

The PAR carriage of {{par-carriage}} is OPTIONAL.

A deployment claiming this profile states the following alongside its
Enforcement Scope Statement ({{I-D.draft-mcguinness-mission-runtime}},
Section "Enforcement Scope and Conformance"):

- which Authorization Servers consume grants, and which of them have
  a Mission-state integration;
- the staleness bound of each one's state gating;
- whether each claims containment- or discharge-aware issuance
  ({{no-state-integration}}); and
- its reconciliation posture ({{security-considerations}}): the
  window within which minting and redemption logs are reconciled, or
  that they are not.

A consuming AS that supports this profile publishes
`mission_issuance_grant_supported`, and one that supports the PAR
carriage publishes `mission_issuance_grant_par_supported`
({{metadata}}).

# Security Considerations {#security-considerations}

The security considerations of {{RFC7523}}, {{RFC7519}}, and
{{RFC8725}} apply. This section adds those specific to the issuance
join.

**Grant theft.** The grant authorizes issuance, so it is defended in
depth: 300-second lifetime, single-use `jti`, audience binding to
one AS, redemption bound to the Mission's `client_id`, and optional
`cnf` key binding. A stolen grant is useless to any party that cannot
also authenticate as the recorded client, or prove possession of the
`cnf` key, at the named AS within the window. Deployments whose
client credentials are weak SHOULD require `cnf` (DPoP {{RFC9449}} or
mTLS {{RFC8705}} bindings serve).

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

**Externally derived authority.** The consuming AS accepts authority
derived elsewhere. Its exposure is bounded by the profile's own
rules: it mints only within the grant's `authorization_details`, only
for the grant's client, never longer than the Mission's `expires_at`,
and its local policy MAY narrow further. The AS remains free to
refuse any grant its policy distrusts; nothing obliges issuance.

**Type confusion.** Three issuer-signed JWT artifacts describe
Missions: the Mandate (evidence), the cross-domain grant (foreign
domain), and this grant (same estate). Explicit typing with mutually
exclusive validation rules ({{Section 3.11 of RFC8725}} and
{{Section 3.12 of RFC8725}}) is the defense: every consumer checks
`typ` first, and none accepts another's type.

**Revocation latency.** New grants stop at the MAS `active` gate at
the moment of state commit. A grant already issued can still be
redeemed within its 300 seconds at a consuming AS without a
Mission-state integration. Issued access tokens run to their own
expiry, and an outstanding refresh token is refused at its next
state-gated use; where the runtime layer is deployed, the PDP's
re-check bounds outstanding-token use independently. A refresh
re-projects through
the Effective Authority Set ({{effective-set-projection}}), so a
Mission contained or discharged between issuance and refresh does
not renew its original, now-narrowed authority. A deployment states
the refresh staleness bound it publishes ({{conformance}}).

**Consent integrity.** The approval the grant rests on was rendered
and committed at the Mission Issuer under the issuance profile's
rules and, where deployed, Consent Evidence
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}). The
consuming AS relies on that event and does not substitute a consent
of its own: its non-prompting duty ({{token-issuance}}) prevents
consent-surface confusion where the Subject holds accounts at both.

# Privacy Considerations {#privacy-considerations}

The grant carries the Mission reference and an authority subset to
the consuming AS, which may be operated by a different organizational
unit than the MAS. Minimization is structural: the MAS scopes
`authorization_details` to what the audience serves ({{minting}}),
and nothing else of the record (no `purpose` text, no Intent, no full
Authority Set) travels. The Mission identifier is a correlator across
MAS and AS logs by design; that correlation is the audit trail, and
deployments that need to limit broader correlation apply the
issuance profile's guidance ({{I-D.draft-mcguinness-oauth-mission}},
Section "Mission Identifier Correlation").

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
{{I-D.draft-mcguinness-mission-authority-server}}:

- Member Name: `mission_issuance_grant_endpoint`
- Change Controller: IETF
- Reference: {{metadata}} of this document

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

# Acknowledgments
{:numbered="false"}

This document profiles the JWT authorization grant of RFC 7523 and
composes the Mission Authority Server with the issuance profile it
already mirrors; it defines no cryptography of its own.
