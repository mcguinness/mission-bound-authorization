---
title: "OAuth 2.0 Mission Tokens"
abbrev: "Mission Tokens"
category: std

docname: draft-mcguinness-oauth-mission-tokens-latest
submissiontype: IETF
workgroup: Web Authorization Protocol
number:
date:
consensus: true
v: 3
keyword:
 - oauth
 - mission
 - token exchange
 - rar
 - lifecycle
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-tokens.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC3339:
  RFC6749:
  RFC6750:
  RFC7009:
  RFC7519:
  RFC7662:
  RFC8414:
  RFC8693:
  RFC8707:
  RFC9068:
  RFC9126:
  RFC9396:
  RFC9449:
  RFC9728:

informative:
  I-D.draft-liu-mcguinness-oauth-bounded-work:
    title: "OAuth 2.0 Bounded Work Authorization"
    target: https://datatracker.ietf.org/doc/draft-liu-mcguinness-oauth-bounded-work/
    author:
      -
        ins: D. Liu
        name: Dapeng Liu
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission/
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-resource-access:
    title: "Mission Resource Access Profile for OAuth 2.0"
    target: https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission-resource-access/
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  RFC9700:
  MISSION-GRANTS:
    title: "OAuth 2.0 Mission Grants"
    target: https://github.com/mcguinness/mission-bound-authorization/blob/main/notes/mission-grants-sketch.md
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

--- abstract

A Mission is an authorization server's durable record of one approval
of OAuth 2.0 Rich Authorization Requests authorization details. This
document represents a Mission to its client as one token: a mission
token, an access token whose audience is the authorization server
itself. The client obtains resource-specific access tokens from it
through OAuth 2.0 Token Exchange, and inspects and ends the Mission
through token introspection and token revocation. Every token issued
from a mission token names the Mission and conveys no more than was
approved. This document defines no new endpoint, grant type, or
request parameter; it adds one token claim, two token response members, one error
response member,
and the rules that make a mission token govern the tokens issued from
it.

--- middle

# Introduction {#introduction}

OAuth 2.0 Rich Authorization Requests {{RFC9396}} let a client request
structured authority, but nothing identifies one approval as a unit:
tokens issued from it carry no common reference, RFC 9396 defines no
comparison for deciding whether a later request stays within it
({{Section 6.1 of RFC9396}}), and ending it means revoking a token
only the client holds.

This document makes the approval that unit, a Mission, and represents
it to the client as a single token. The client requests a Mission by
naming the authorization server itself as the resource of an ordinary
authorization request. After approval, the token response carries a
mission token: an access token for the authorization server that
holds the approved authority for the Mission's whole lifetime. Then:

- the client exchanges the mission token for access tokens to
  specific resources through Token Exchange {{RFC8693}}; each issued
  token names the Mission and conveys no more than was approved;
- introspection {{RFC7662}} reports the mission token, and every token
  issued from it, active only while the Mission is active; and
- revoking the mission token {{RFC7009}} ends the Mission.

A client and a resource server use only endpoints they already know.
This document adds the `mission` token claim, the `mission_id` and
`mission_expires_at` token response members, the `mission_error` error
response member, two metadata flags, and these rules: how a
mission token is requested and bound, what an exchange may issue from
it, and how its state governs the tokens issued from it. It defines no
description of the work; a separate specification can add one
({{extension-points}}).

The framework for approved bounded work
{{I-D.draft-liu-mcguinness-oauth-bounded-work}} names a governing
authorization; a Mission realizes it, and {{bounded-work-mapping}}
maps this document to that framework's requirements. Mission-Bound
Authorization for OAuth 2.0 {{I-D.draft-mcguinness-oauth-mission}}
defines a Mission that also records a description of the task; the
`mission` claim and the `mission_error` values this document shares
with it have the same meaning.

## Conventions and Terminology {#terminology}

{::boilerplate bcp14-tagged}

This document uses the terms authorization server, client, resource
server, resource owner, and access token from {{RFC6749}};
authorization details from {{RFC9396}}; and subject token from
{{RFC8693}}.

Mission:
: An authorization server's durable record of one approval of
  authorization details, with a lifecycle ({{lifecycle}}).

Approved Authority:
: The `authorization_details` array the approval established for a
  Mission.

Mission token:
: The access token that represents a Mission to its client: its
  audience is the authorization server, and it carries the Approved
  Authority ({{mission-token}}).

Mission-bound token:
: A mission token, or an access token issued from one by Token
  Exchange.

Mission-governed operation:
: An operation that a resource server performs only for a
  Mission-bound access token ({{rs-enforcement}}).

# Protocol Overview {#overview}

~~~ ascii-art
Client                 Authorization Server       Resource Server
  |                             |                         |
  |-(1) authorization request ->|                         |
  |     resource=<AS issuer>,   |                         |
  |     authorization_details   |                         |
  |                             |-(2) approval;           |
  |                             |     Mission created     |
  |<-(3) code ------------------|                         |
  |-(4) token request --------->|                         |
  |<-(5) mission token ---------|                         |
  |-(6) token exchange:         |                         |
  |     subject_token=          |                         |
  |     mission token,          |                         |
  |     resource=<RS> --------->|                         |
  |<-(7) resource access token -|                         |
  |-(8) request with resource access token -------------->|
  |                             |                         |
  |-(9) introspect or revoke    |                         |
  |     the mission token ----->|                         |
~~~
{: title="A Mission token from approval to use"}

# Obtaining a Mission Token {#obtaining}

## Request {#request}

A client requests a Mission with an authorization request that carries
`authorization_details` {{RFC9396}} and, as its only `resource`
{{RFC8707}}, the authorization server's issuer identifier
{{RFC8414}}. The token request that redeems the code names the same
`resource`. The request can also carry `scope`, as
{{Section 3.1 of RFC9396}} allows, but a Mission-bound token conveys
no authority through it ({{subset}}). A
client SHOULD send the request as a Pushed Authorization Request
{{RFC9126}}.

The authorization server MUST refuse, with `invalid_target`
({{Section 2 of RFC8707}}), a request that carries
`authorization_details` and names its issuer identifier together with
another `resource`, since a mission token has exactly
one audience. An authorization server that implements this document MUST
NOT also implement OAuth 2.0 Mission Grants {{MISSION-GRANTS}} at the
same issuer, so a client and a resource server can tell from the
issuer's metadata which rules govern its Missions ({{metadata}}).

A client first establishes that the authorization server advertises
`mission_tokens_supported` ({{metadata}}). An authorization server
that does not implement this document can refuse the request with
`invalid_target`, or issue an ordinary access token for itself. A
client that has not established support MUST NOT treat the issued
token as a mission token or use tokens obtained from it for the work
it requested the Mission for. A client that receives a token response
without `mission_id` ({{token-response}}) likewise MUST NOT use the
issued token for the work, and SHOULD revoke it {{RFC7009}}.

## Approval {#approval}

The authorization server establishes the Approved Authority from the
requested `authorization_details`. It MAY narrow the request under its
policy, and the resource owner MAY narrow it further. Each entry of
the Approved Authority MUST be of the same type as a requested entry
and MUST grant no more than that entry; an entry is never widened and
entries are never combined. Before approval, the authorization server
presents the authority it will approve, as it will be granted, in
terms the resource owner can understand.

The resource owner approves, and the authorization server
authenticates them. An approval decision creates the Mission and the
authorization code together: the authorization server issues the code
only when the Mission is recorded, and a declined or abandoned request
creates neither. The Mission can end before the client redeems the
code; the redemption is then refused ({{gating}}).

## Token Response {#token-response}

The token response that redeems the code carries the mission token as
its `access_token`, and the Approved Authority as
`authorization_details` ({{Section 7 of RFC9396}}). The authorization
server:

- issues the mission token only while the Mission is `active`
  ({{gating}});
- carries `mission_id` and `mission_expires_at`, below;
- MUST bind the mission token to the key of the DPoP proof in the
  token request ({{Section 5 of RFC9449}}), and MUST refuse a token
  request for a mission token that carries no DPoP proof, with
  `invalid_request`;
- MUST NOT issue a refresh token with a mission token: the mission
  token lasts as long as the Mission; and
- sets `expires_in` to the time remaining until the Mission's expiry.

`mission_id`:
: A string: the Mission Identifier. It is a reference only; presenting
  it authorizes nothing.

`mission_expires_at`:
: The exact RFC 3339 {{RFC3339}} string of the Mission's expiry.

The client learns its Mission from these members, not from the mission
token, which it treats as opaque ({{Section 6 of RFC9068}}).

# The Mission and the Mission Token {#mission-token}

A Mission is a logical record at the authorization server with these
facts: its identifier; the authorization server's issuer identifier;
the client it was approved for; the resource owner who approved; the
instant of approval; its expiry, set by the authorization server; the
Approved Authority; and its state ({{lifecycle}}). Everything except
the state is fixed when the Mission is created. More authority than
the Approved Authority requires a new Mission through a new approval.

A Mission Identifier is an opaque string of the characters
`[A-Za-z0-9_-]`, carries at least 128 bits of entropy, and is unique at
its authorization server.

The mission token is an access token, either a JWT {{RFC9068}} or an
opaque token the authorization server introspects. Its audience is the
authorization server's issuer identifier, so a resource server
rejects it. The authorization server accepts it only at its token
endpoint for Token Exchange, at introspection, and at revocation: a
resource it hosts, such as UserInfo or an account API, MUST refuse a
mission token. It carries the `mission` claim, the Approved Authority as
`authorization_details`, an expiry equal to the Mission's, and the
DPoP key binding. The authorization server issues exactly one mission
token for a Mission and never reissues it.

The `mission` claim is a JSON object:

`id`:
: REQUIRED. A string: the Mission Identifier.

`issuer`:
: REQUIRED. A string: the authorization server's issuer identifier.

# Exchanging for Resource Tokens {#exchange}

## Request {#exchange-request}

The client obtains an access token for a resource with a Token
Exchange request ({{Section 2.1 of RFC8693}}) whose `subject_token` is
the mission token, or an access token issued from it, with
`subject_token_type` `urn:ietf:params:oauth:token-type:access_token`.
It names the target with `resource` or `audience`, and can narrow the
authority with `authorization_details`. An exchange carries no
`actor_token`, and the authorization server refuses one with
`invalid_request`; delegation to another party is left to a
specification ({{extension-points}}).

**Proof of possession.** RFC 9449 binds an issued token to the key of
the token request's DPoP proof, but does not require that proof to
match the key of a sender-constrained subject token. For an exchange
whose subject token is Mission-bound, this document does: the
authorization server MUST verify that the request's DPoP proof is
signed with the key the subject token is bound to, and MUST refuse
the request otherwise, with `invalid_request`
({{Section 2.2.2 of RFC8693}}). The authorization server SHOULD require
a DPoP server nonce ({{Section 8 of RFC9449}}) at Token Exchange, so
that proofs for a key that lasts the Mission's lifetime cannot be
made ahead of use.

The authorization server MUST check an exchange in this order and MUST
refuse it at the first failure, with `invalid_request`
({{Section 2.2.2 of RFC8693}}) unless a step names another code:

1. the client's authentication, as at its token endpoint;
2. that the subject token is a Mission-bound access token the
   authorization server issued, by its signature or its own record;
3. the proof of possession above;
4. issuance gating ({{gating}}), which refuses with `mission_error`
   when the Mission is not `active`, including when it has expired;
5. the subject token's own expiry; and
6. the subset rule ({{subset}}), with its own error codes.

Only an exchange that passes steps 1 to 3 can receive `mission_error`,
so a party that cannot prove possession of the subject token learns
nothing about the Mission.

## Issued Token {#issued-token}

A token issued from a Mission-bound subject token:

- is an access token: the response's `issued_token_type` is
  `urn:ietf:params:oauth:token-type:access_token`
  ({{Section 2.2.1 of RFC8693}});
- has the target the request names as its audience;
- carries the same `mission` claim;
- conveys `authorization_details` under the subset rule
  ({{subset}});
- has an expiry no later than the subject token's; and
- is bound to the key of the request's DPoP proof
  ({{Section 5 of RFC9449}}).

The authorization server MUST refuse, with `invalid_request`, such an
exchange whose `requested_token_type` names any other token type, and
MUST NOT include a `refresh_token` in its response, although
{{Section 2.2.1 of RFC8693}} permits one. Code redemption and
exchange are therefore the only paths that issue Mission-bound tokens,
and both are gated ({{gating}}).

## The Subset Rule {#subset}

Each entry of the `authorization_details` of a token issued by
exchange MUST meet three conditions:

1. **Within the subject token's authority.** It is an entry of the
   subject token's `authorization_details` carried unchanged, or a
   narrowing of one such entry under a comparison that the entry's type
   defines. It never combines rights from several entries.
2. **Within the request.** Where the exchange carries
   `authorization_details`, it is a requested entry or a narrowing of
   one. An approved entry broader than the requested one is never
   issued in its place.
3. **For the audience.** It applies to every audience of the issued
   token: its `locations` ({{Section 2.2 of RFC9396}}) include the
   audience value, compared as strings, or its type defines how it
   applies to that audience. An entry with neither applies nowhere.

Where the exchange carries no `authorization_details`, the
authorization server issues the entries of the subject token's
authority that apply to the audience, unchanged. It MUST refuse an
exchange that carries `authorization_details` with
`invalid_authorization_details` ({{Section 6 of RFC9396}}) when a
requested entry fails a condition, or needs a comparison that the
entry's type does not define or that cannot decide it; and MUST refuse
an exchange that carries none with `invalid_target`
({{Section 2.2.2 of RFC8693}}) when no entry of the subject token's
authority applies to the audience.

The rule applies at every exchange. When the subject token was itself
issued by exchange, its authority, already narrowed and filtered to its
audience, is the bound, so a chain only narrows. The Mission Resource
Access Profile {{I-D.draft-mcguinness-oauth-mission-resource-access}}
is an example of a type specification that defines a comparison. This
document defines no way to discover which narrowings an authorization
server accepts; a client that needs one learns from the refusal.

A Mission-bound access token carries no `scope`, in the token or in an
introspection response, unless a specification that bounds `scope` by
the Approved Authority applies ({{extension-points}}). A `scope` value
requested with a Mission, such as `openid`, keeps its own meaning
outside the Mission and conveys no authority through a Mission-bound
token.

## Issuance Gating {#gating}

The authorization server MUST NOT issue a Mission-bound token unless
the Mission is `active` at the instant of issuance: neither the
mission token when it redeems the code, nor a token from a
Mission-bound subject token. It refuses a code redemption with
`invalid_grant` ({{Section 5.2 of RFC6749}}) and an exchange with
`invalid_request` ({{Section 2.2.2 of RFC8693}}), and adds this member
to either error response:

`mission_error`:
: A string: the Mission's state, `revoked` or `expired`.

A client that receives `mission_error`, with any value, stops the
work and does not seek another credential for it.

At code redemption, the authorization server validates the code as
{{RFC6749}} requires, and the DPoP proof, before it applies this gate;
at Token Exchange it follows the order of {{exchange-request}}. It
returns `mission_error` only for an otherwise valid code or subject
token.

# Lifecycle, Introspection, and Revocation {#lifecycle}

A Mission is `active` from approval until it ends, then `revoked` or
`expired`; both are terminal. Only `active` permits issuance from the
Mission's tokens or reliance on them. A party treats a state it does
not recognize as an ended Mission.

**Expiry.** When its expiry passes, the Mission is `expired`, and so
is its mission token.

**Revocation.** Any revocation of the mission token ends its Mission
(`revoked`): by the client, with RFC 7009, which lets a client revoke
only tokens issued to it ({{Section 2.1 of RFC7009}}) and leaves
revoking related tokens to the authorization server's policy; or by
the authorization server, for example on detecting reuse of the
authorization code ({{Section 4.1.2 of RFC6749}}). Revoking a token
issued from the mission token revokes only that token.

**Ending without a token.** The authorization server MUST offer the
resource owner a means to end the resource owner's Missions without
holding any token, such as account settings. This document does not
define that means; a specification can define one
({{extension-points}}).

**Introspection.** An introspection response {{RFC7662}} reports a
Mission-bound token active only while its Mission is active, and an
active response carries the `mission` member and the token's
`authorization_details`. RFC 7662 requires authorization at the
introspection endpoint and leaves who may call it to the authorization
server; the authorization server SHOULD let the client introspect its
own mission token, authenticating as it does at the token endpoint.
An inactive response does not say why the token is inactive
({{Section 2.2 of RFC7662}}). The mission token ends only when its
Mission ends, so where the authorization server lets the client
introspect it, an inactive response means the Mission has ended; for
a token issued by exchange, it can also mean that the token alone
expired or was revoked.

**Acceptance after ending.** Ending a Mission stops issuance at once.
A JWT access token already issued from it remains acceptable to a
resource server that relies on the token alone until its `exp`; a
resource server that introspects each use sees the ending at its next
introspection. The authorization server SHOULD keep the lifetime of
tokens issued by exchange short. Ending a Mission does not undo
effects already accepted.

# Resource Server Enforcement {#rs-enforcement}

For an operation it protects under this document, a resource server:

1. validates the access token, from the token itself {{RFC9068}} or
   by introspection {{RFC7662}}, including its DPoP binding and its
   audience, so it rejects a mission token;
2. requires the `mission` member, and requires `mission.issuer` to
   equal the token's issuer, which it trusts to issue Mission-bound
   tokens;
3. treats the carried `authorization_details` as the authoritative
   statement of the token's authority, using only the entries that apply
   to it ({{subset}}): where several entries apply
   they are alternative grants, an entry it cannot fully enforce
   grants nothing, and it never combines parts of several entries;
4. grants nothing, for a Mission-governed operation, on the basis of
   a `scope` value the token carries; and
5. relies on the Mission's state in one of two ways ({{lifecycle}}):
   it introspects the token at use, and an active response shows that
   the Mission is active at that instant; or it accepts a JWT until its
   `exp`, and so may accept it for up to that time after the Mission
   ends.

A resource server MUST refuse an access token without the `mission`
member for a Mission-governed operation, with `invalid_token` and the
`resource_metadata` parameter ({{Section 5.1 of RFC9728}}), and
declares such operations in that protected resource metadata:

`mission_tokens_required`:
: A boolean. `true` declares that the resource's protected operations
  are Mission-governed. Absent means `false`.

A client that receives that refusal for a token without `mission`
obtains a Mission-bound token, rather than another of the same kind.

Denials distinguish three causes: the Mission has ended
(`invalid_token`, with a `mission_error` parameter carrying the state
where the resource server knows it, which is advisory: the client
confirms it at the authorization server, by introspecting its mission
token or attempting an exchange, before it stops the work); the
operation is outside the carried authority (`insufficient_scope`
{{RFC6750}}: the client exchanges for a token that covers it where the
Approved Authority does, and otherwise needs a new Mission); or only
the credential failed (`invalid_token`). Where more than one applies, an
ended Mission takes precedence. An inactive introspection response
does not tell a resource server whether the credential or the Mission
ended ({{Section 2.2 of RFC7662}}); it then responds `invalid_token`
without `mission_error`.

# Authorization Server Metadata {#metadata}

This document defines one authorization server metadata parameter
{{RFC8414}}:

`mission_tokens_supported`:
: A boolean. `true` declares that the authorization server implements
  this document. Absent means `false`.

An authorization server that advertises `mission_tokens_supported`
MUST NOT advertise `mission_grants_supported` ({{request}}).

An authorization server that sets it lists
`urn:ietf:params:oauth:grant-type:token-exchange` in
`grant_types_supported`, and the authorization details types it
accepts in `authorization_details_types_supported`
({{Section 10 of RFC9396}}).

# Extension Points {#extension-points}

A specification that extends Missions can:

- define approval by a party other than the resource owner, or record
  a description of the work, as further facts fixed with the Mission;
- define a means for a party holding no token to end a Mission or read
  its state by its identifier;
- define delegation to another party at exchange, such as through an
  `actor_token`;
- define how `scope` is bounded by the Approved Authority, so that a
  Mission-bound token can carry it;
- define further Mission states and `mission_error` values; and
- define, for a type of authorization details, the comparison the
  subset rule uses ({{subset}}).

No extension widens the Approved Authority, permits issuance or
reliance in any state other than `active`, or reactivates an ended
Mission.

# Security Considerations {#security}

**A long-lived token.** A mission token holds the whole Approved
Authority for the Mission's lifetime. Three rules contain it: its
audience is the authorization server, which accepts it only at token
exchange, introspection, and revocation; it is DPoP-bound; and an exchange must prove possession of its
key ({{exchange-request}}). Without the last rule, a copied mission
token presented with any fresh DPoP key would yield resource tokens.
The security best current practice {{RFC9700}} applies.

**The approval sets the ceiling.** The subset rule bounds every
exchange by the subject token's authority, the client's request, and
the audience, and a narrowing the type cannot compare is refused
rather than guessed. Exchanges chain: a token issued from an issued
token narrows further, never wider. Neither a refresh token nor a
reissued mission token offers another path ({{issued-token}}).

**Acceptance after ending.** Tokens already issued outlive the ending
by up to their lifetime ({{lifecycle}}).

**Ending authority.** A client ends its own Mission by revoking the
mission token. A party that must stop the work without the client's
cooperation depends on the authorization server's own means
({{lifecycle}}), which this document does not make interoperable.

**Downgrade.** A client that has not established support does not use
the token for the work ({{request}}), and a resource server refuses
tokens without a Mission for Mission-governed operations
({{rs-enforcement}}).

# Privacy Considerations {#privacy}

The Mission Identifier joins every token of a Mission, so a party that
sees several can link them; it is opaque and carries no information
about the resource owner or the work. The `mission` claim carries only
the identifier and issuer. A token issued by exchange carries only the
entries that apply to its audience ({{subset}}), so a resource server
does not learn authority approved for another.

# IANA Considerations {#iana}

The `mission` claim and introspection member, and the `mission_error`
member, share their names and meanings with Mission-Bound
Authorization for OAuth 2.0 {{I-D.draft-mcguinness-oauth-mission}},
which requests the same registrations. In this document
`mission_error` accompanies `invalid_grant` at code redemption, as in
that document, and the `invalid_request` error code that RFC 8693
requires for an exchange. The documents are expected to converge on
one registration.

This document requests registration of:

- `mission` in the "JSON Web Token Claims" registry {{RFC7519}}, with
  Description "Mission reference" and Reference {{mission-token}};
- `mission` in the "OAuth Token Introspection Response" registry, with
  Description "Mission reference" and Reference {{lifecycle}};
- `mission_id` and `mission_expires_at` in the "OAuth Parameters"
  registry, usage location token response, Reference {{token-response}},
  which OAuth 2.0 Mission Grants requests with the same meaning;
- `mission_error` in the "OAuth Parameters" registry, usage location
  token error response, Reference {{gating}};
- `mission_tokens_supported` in the "OAuth Authorization Server
  Metadata" registry, Reference {{metadata}}; and
- `mission_tokens_required` in the "OAuth Protected Resource Metadata"
  registry, Reference {{rs-enforcement}}.

--- back

# The Bounded Work Framework's Requirements {#bounded-work-mapping}
{:numbered="false"}

This appendix is informative. It maps the requirements of the
framework for approved bounded work
{{I-D.draft-liu-mcguinness-oauth-bounded-work}} to this document.

| Requirement | Met by |
|---|---|
| R1: an identifier distinct from the client, any token, and any refresh token family | The Mission Identifier in the `mission` claim; one mission token per Mission, never reissued ({{mission-token}}) |
| R2: what was approved is fixed; more authority creates a new authorization | The fixed Mission and a new Mission for more authority ({{mission-token}}). It fixes the approved authority and the resource owner who approved, not the request; an accountable approver other than the resource owner, and a description of the work, are left to extensions. |
| R3: no credential broader than the approved bounds, refusing where the comparison cannot decide | The subset rule at exchange ({{subset}}) |
| R4: every issuance path refuses once ended | Issuance gating at code redemption and at exchange, the only issuance paths: no refresh token is issued with the mission token or by exchange ({{gating}}, {{issued-token}}) |
| R5: a party holding no token ends one authorization without affecting the client's other work | Partly: the client revokes the mission token; a party holding no token uses the authorization server's own means, which this document requires but does not define ({{lifecycle}}) |
| R6: issued credentials stop being accepted within a stated time | Exchanged token lifetime, or introspection ({{lifecycle}}) |
| R7: a second party relates each credential to its authorization without inference | The `mission` claim and introspection member |
| R8: an authorized second party asks whether an authorization is active | Partly: introspection of a Mission-bound token it holds; a query by identifier is left to an extension |
{: title="Bounded work requirements"}

# Example {#example}
{:numbered="false"}

The client pushes an authorization request naming the authorization
server as the resource (line breaks for display):

~~~ http-message
POST /par HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

response_type=code
&client_id=agent-7
&redirect_uri=https%3A%2F%2Fagent.example%2Fcb
&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
&code_challenge_method=S256
&resource=https%3A%2F%2Fas.example.com
&authorization_details=%5B%7B%22type%22%3A%22payment_initiation%22%2C
%22actions%22%3A%5B%22initiate%22%5D%2C%22locations%22%3A%5B
%22https%3A%2F%2Fpay.example.com%22%5D%7D%5D
&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3A
client-assertion-type%3Ajwt-bearer
&client_assertion=eyJhbGciOiJFUzI1NiJ9...
~~~

After approval, the token response carries the mission token and no
refresh token:

~~~ json
{
  "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCJ9...",
  "token_type": "DPoP",
  "expires_in": 86400,
  "mission_id": "msn_K9iLTMIDFUiBucaPegc_B4lY",
  "mission_expires_at": "2026-11-20T09:00:00Z",
  "authorization_details": [
    {
      "type": "payment_initiation",
      "actions": ["initiate"],
      "locations": ["https://pay.example.com"]
    }
  ]
}
~~~

The mission token's claims include:

~~~ json
{
  "iss": "https://as.example.com",
  "aud": "https://as.example.com",
  "client_id": "agent-7",
  "exp": 1795165200,
  "cnf": { "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" },
  "mission": {
    "id": "msn_K9iLTMIDFUiBucaPegc_B4lY",
    "issuer": "https://as.example.com"
  },
  "authorization_details": [
    {
      "type": "payment_initiation",
      "actions": ["initiate"],
      "locations": ["https://pay.example.com"]
    }
  ]
}
~~~

The client exchanges it for a token to the payment service, with a
DPoP proof signed by the mission token's key:

~~~ http-message
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
DPoP: eyJ0eXAiOiJkcG9wK2p3dCJ9...

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange
&subject_token=eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCJ9...
&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3A
access_token
&resource=https%3A%2F%2Fpay.example.com
&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3A
client-assertion-type%3Ajwt-bearer
&client_assertion=eyJhbGciOiJFUzI1NiJ9...
~~~

The approved entry's `locations` include the payment service, so the
entry applies there. The response carries an access token and no
refresh token:

~~~ json
{
  "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCJ9...",
  "issued_token_type":
    "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "DPoP",
  "expires_in": 300,
  "authorization_details": [
    {
      "type": "payment_initiation",
      "actions": ["initiate"],
      "locations": ["https://pay.example.com"]
    }
  ]
}
~~~

The issued token has audience `https://pay.example.com`, the same
`mission` claim, the same `authorization_details`, and an `exp` of
1795080900, five minutes after issue. Later, the client ends the
Mission:

~~~ http-message
POST /revoke HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

token=eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCJ9...
&token_type_hint=access_token
&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3A
client-assertion-type%3Ajwt-bearer
&client_assertion=eyJhbGciOiJFUzI1NiJ9...
~~~

A later exchange is refused:

~~~ json
{
  "error": "invalid_request",
  "mission_error": "revoked"
}
~~~

# Document History {#document-history}
{:numbered="false"}

\[\[ To be removed from the final specification ]]

-00

- Initial version: a Mission represented as one mission token for the
  authorization server, exchanged for resource tokens through Token
  Exchange, inspected through introspection, and ended through
  revocation.
