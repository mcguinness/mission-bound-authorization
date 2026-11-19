---
title: "OAuth 2.0 Mission Grants"
abbrev: "Mission Grants"
category: std

docname: draft-mcguinness-oauth-mission-grants-latest
submissiontype: IETF
workgroup: Web Authorization Protocol
number:
date:
consensus: true
v: 3
keyword:
 - oauth
 - mission
 - rar
 - refresh token
 - lifecycle
 - revocation
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-grants.html"

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
  RFC8259:
  RFC8414:
  RFC8693:
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

--- abstract

A Mission is an authorization server's durable record of one approval
of OAuth 2.0 Rich Authorization Requests authorization details. A
client requests a Mission by adding one parameter to an ordinary
authorization request. Every token issued under the Mission names it,
conveys no more than was approved, and stops being issued once the
Mission ends; a party holding none of its tokens can end the Mission,
and ask whether it is active, by its identifier. This document defines
the Mission and its identifier, the `mission` token claim, issuance
gated on the Mission's state, a lifecycle, and a management endpoint.
It defines no description of the work; a separate specification can
add one.

--- middle

# Introduction {#introduction}

OAuth 2.0 Rich Authorization Requests {{RFC9396}} let a client request
structured authority, and a refresh token {{RFC6749}} lets it keep
obtaining access tokens for that authority after the resource owner
approves. Neither identifies the approval as a unit:

- tokens issued from one approval carry no common reference that a
  resource server or an auditor can follow back to it;
- RFC 9396 defines no comparison for deciding whether a later token
  request stays within what was approved ({{Section 6.1 of RFC9396}});
  and
- ending the approval means revoking a refresh token, which only the
  client holds.

This document makes the approval that unit. A Mission is the
authorization server's durable record of one approval of
`authorization_details`. The client requests a Mission by adding the
`mission_expires_in` parameter to an authorization request. After
approval:

- the Mission has an identifier, distinct from the client and from
  every token it issues;
- what was approved is fixed, and more authority requires a new
  Mission;
- every token issued under the Mission names it and conveys no more
  than was approved;
- the authorization server issues nothing under the Mission once it
  has ended; and
- a party holding none of its tokens can end the Mission, and ask
  whether it is active, by its identifier.

This document defines no new grant type and no description of the
work. A specification that adds a description, or other inputs to the
approval, does so through the extension points of {{extension-points}}.

The framework for approved bounded work
{{I-D.draft-liu-mcguinness-oauth-bounded-work}} names a governing
authorization with these properties; a Mission realizes it, and
{{bounded-work-mapping}} maps this document to that framework's
requirements. Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} defines a Mission that also
records a description of the task and adds further mechanisms; the
token claim, response parameters, and error member this document
shares with it have the same meaning.

## Conventions and Terminology {#terminology}

{::boilerplate bcp14-tagged}

This document uses the terms authorization server, client, resource
server, resource owner, access token, refresh token, and authorization
code from {{RFC6749}}, and authorization details from {{RFC9396}}.

Mission:
: An authorization server's durable record of one approval of
  authorization details, with a lifecycle ({{lifecycle}}).

Mission Identifier:
: The string that identifies a Mission at the authorization server
  that holds it ({{record}}).

Approved Authority:
: The `authorization_details` array the approval established for a
  Mission.

Mission grant lineage:
: The authorization code issued at a Mission's approval and the
  refresh tokens issued from it.

Mission-bound token:
: An access token or refresh token issued under a Mission.

Mission-governed operation:
: An operation that a resource server performs only for a
  Mission-bound access token ({{rs-enforcement}}).

# Protocol Overview {#overview}

~~~ ascii-art
Client                 Authorization Server       Resource Server
  |                             |                         |
  |-(1) authorization request ->|                         |
  |     authorization_details,  |                         |
  |     mission_expires_in      |                         |
  |                             |-(2) approval;           |
  |                             |    Mission created      |
  |<-(3) authorization code ----|                         |
  |-(4) token request --------->|                         |
  |<-(5) tokens, mission_id, ---|                         |
  |      mission_expires_at     |                         |
  |-(6) request with access token (mission claim) ------->|
  |                             |  (7) Mission active,    |
  |                             |      and within the     |
  |                             |      approved authority?|
  |-(8) refresh --------------->|                         |
  |    (issued only while the   |                         |
  |     Mission is active)      |                         |
~~~
{: title="A Mission from approval to use"}

1. The client sends an authorization request with
   `authorization_details` and `mission_expires_in` ({{requesting}}).
2. The resource owner, or an approver acting for the resource owner,
   approves; the authorization server creates the Mission ({{approval}}).
3. and 4. The client redeems the authorization code.
5. The token response carries the Mission Identifier and expiry
   ({{token-response}}).
6. and 7. The resource server checks the token, the Mission's state,
   and the operation against the carried authority ({{rs-enforcement}}).
8. Refresh, and any other issuance under the Mission, succeeds only
   while the Mission is active ({{gating}}).

At any time, an authorized party can end the Mission or read its state
at the management endpoint ({{management}}).

# Requesting a Mission {#requesting}

This document defines the following authorization request parameter:

`mission_expires_in`:
: A positive integer: the requested maximum lifetime of the Mission,
  in seconds from approval. Its presence requests a Mission.

A request that carries `mission_expires_in` MUST also carry
`authorization_details` {{RFC9396}}. The authorization server MUST
refuse a request that carries `mission_expires_in` without
`authorization_details`, or with a value that is not a positive
integer, with the `invalid_request` error code. A client SHOULD send
the request as a Pushed Authorization Request {{RFC9126}}. The request
can also carry `scope`, as {{Section 3.1 of RFC9396}} allows; this
document does not govern it.

A client learns that it will not get a Mission from the absence of
`mission_grants_supported` ({{metadata}}) before it sends the request,
and from the absence of `mission_id` in the token response after it.
An authorization server that does not implement this document can
ignore `mission_expires_in` as an unrecognized parameter
({{Section 3.1 of RFC6749}}), or refuse a pushed request that carries
it. A client that requested a Mission and receives a token response
without `mission_id` MUST NOT use the issued tokens for the work it
requested the Mission for, and SHOULD revoke them {{RFC7009}}.

# Approval and Creation {#approval}

The authorization server establishes the Approved Authority from the
requested `authorization_details`. It MAY narrow the request under its
policy, and the approver MAY narrow it further. Each entry of the
Approved Authority MUST be of the same type as a requested entry and
MUST grant no more than that entry; an entry is never widened and
entries are never combined. Before approval, the authorization server
presents the authority it will approve, as it will be granted, in
terms the approver can understand.

The approver is the resource owner, or a party the authorization
server's policy authorizes to approve for the resource owner; the
authorization server authenticates the approver and verifies that
authorization. An approval decision creates the Mission and the
authorization code together: the authorization server issues the code
only when the Mission is recorded, and a declined or abandoned request
creates neither.

# The Mission Record {#record}

A Mission Record is a JSON object {{RFC8259}} with these members:

`id`:
: REQUIRED. A string: the Mission Identifier.

`issuer`:
: REQUIRED. A string: the authorization server's issuer identifier
  {{RFC8414}}.

`client_id`:
: REQUIRED. A string: the client the Mission was approved for.

`sub`:
: REQUIRED. A string: the resource owner the authority is exercised
  for, as the authorization server identifies them.

`approver`:
: REQUIRED. A string: the party that approved, in the same identifier
  space the authorization server uses for `sub`. It equals `sub` when
  the resource owner approved.

`approved_at`:
: REQUIRED. A string: an RFC 3339 {{RFC3339}} date-time, the instant
  of approval.

`expires_at`:
: REQUIRED. A string: an RFC 3339 date-time set by the authorization
  server. It MUST be later than `approved_at` and MUST NOT be later
  than `approved_at` plus the requested `mission_expires_in`.

`authorization_details`:
: REQUIRED. The Approved Authority.

`state`:
: REQUIRED. A string: the Mission's lifecycle state ({{lifecycle}}).

`termination`:
: Present exactly when `state` is `terminated`. An object with
  `reason`, a string from the Mission Termination Reasons registry
  ({{iana-reasons}}), and `terminated_at`, an RFC 3339 date-time.

Every member except `state` and `termination` is fixed when the
Mission is created and never changes. `termination` is written once.
More authority than the Approved Authority requires a new Mission
through a new approval; the existing Mission continues under its own
Approved Authority until it ends.

A Mission Identifier is an opaque string of the characters
`[A-Za-z0-9_-]`, carries at least 128 bits of entropy, and is unique at
its authorization server. The pair (`issuer`, `id`) identifies a
Mission globally. The record is a logical object: this document
requires no storage form, and its JSON form governs wherever the
record, or a part of it, is exchanged.

# Mission-Bound Tokens {#tokens}

## Token Response {#token-response}

The token response that redeems a Mission's authorization code MUST
carry, besides the tokens and the granted `authorization_details`
({{Section 7 of RFC9396}}):

`mission_id`:
: A string: the Mission Identifier. It is a reference only; presenting
  it authorizes nothing.

`mission_expires_at`:
: The exact RFC 3339 string of the Mission's `expires_at`. The
  `expires_in` parameter describes the access token's lifetime, not
  the Mission's.

Any other token response under a Mission SHOULD carry both.

## Mission Grant Lineage {#lineage}

The authorization code issued at a Mission's approval, and every
refresh token issued from it, belong to that Mission and to no other.
Each Mission has its own lineage: creating a Mission replaces no
refresh token the client already holds, for this or any other Mission
or grant.

## The mission Claim {#mission-claim}

The `mission` claim is a JSON object:

`id`:
: REQUIRED. A string: the Mission Identifier.

`issuer`:
: REQUIRED. A string: the Mission's `issuer`.

A JWT access token {{RFC9068}} issued under a Mission MUST carry the
`mission` claim and the `authorization_details` it grants, and its
`exp` MUST NOT be later than the Mission's `expires_at`. An
introspection response {{RFC7662}} for an opaque Mission-bound access
token carries the same `mission` member and `authorization_details`
when the token is active. A Mission-bound token is active only while
its Mission is active.

## The Subset Rule {#subset}

Every token the authorization server issues under a Mission, by code
redemption, refresh, or Token Exchange {{RFC8693}}, conveys
`authorization_details` each entry of which is either:

- an entry of the Approved Authority, carried unchanged; or
- a narrowing of one entry of the Approved Authority under a
  comparison that the entry's type defines.

An issued entry never combines rights from several entries. Where a
request asks for a narrowing that the entry's type defines no
comparison for, or that the comparison cannot decide, the
authorization server MUST refuse the request with the
`invalid_authorization_details` error code ({{Section 6 of RFC9396}}).
The Mission Resource Access Profile
{{I-D.draft-mcguinness-oauth-mission-resource-access}} is an example of
a type specification that defines such a comparison. This document
defines no way to discover which narrowings an authorization server
accepts; a client that needs one learns from the refusal.

A token issued by Token Exchange from a Mission-bound subject token
carries the same `mission` claim, is subject to this rule, and is
gated on the same Mission ({{gating}}).

## Issuance Gating {#gating}

The authorization server MUST NOT issue a token under a Mission, at
any issuance path, unless the Mission is `active` at the instant of
issuance. It refuses a token request under a Mission that is not
active with the `invalid_grant` error code and this member of the
error response:

`mission_error`:
: A string: the Mission's termination reason, `revoked` or `expired`,
  or another registered reason ({{iana-reasons}}).

A client that receives `mission_error`, with any value, stops the
work and does not seek another credential for it: no retry under the
same Mission succeeds.

# Lifecycle {#lifecycle}

A Mission is in one of two states:

- `active`: the only state in which the authorization server issues
  tokens under it and a resource server relies on it.
- `terminated`: a terminal state.

| From | Event | To | Termination reason |
|---|---|---|---|
| (none) | approval | `active` | |
| `active` | revocation | `terminated` | `revoked` |
| `active` | `expires_at` reached | `terminated` | `expired` |
{: title="Mission lifecycle"}

A Mission is revoked when an authorized party ends it at the
management endpoint ({{management}}), or when its grant lineage is
revoked: the client revoking a refresh token of the lineage
{{RFC7009}}, or the authorization server revoking the lineage, for
example on detecting refresh token replay. So a client ends its own
Mission by revoking its refresh token. Rotation, which replaces a
refresh token with another of the same lineage, is not revocation.

A specification can register further states ({{iana-states}}) and
termination reasons ({{iana-reasons}}). A party treats a state it does
not recognize as not active, and a termination reason it does not
recognize as an ending.

Ending a Mission stops issuance at once. An access token already
issued remains acceptable to a resource server that relies on the
token alone until the token's `exp`; a resource server that
introspects each use sees the ending at its next introspection. The
interval in which an ended Mission's tokens can still be accepted is
therefore bounded by access token lifetime, which the authorization
server SHOULD keep short. Ending a Mission does not undo effects
already accepted.

# Management Endpoint {#management}

An authorization server that implements this document offers a
management endpoint, which it advertises as
`mission_management_endpoint` ({{metadata}}). The resource for a
Mission is the endpoint URL followed by `/` and the Mission Identifier
as a path segment.

Every request to the endpoint carries an access token issued for the
endpoint, presented as {{RFC6750}} or, for a DPoP-bound token,
{{RFC9449}} describes. A missing or invalid access token, or one not
issued for the endpoint, such as a Mission-bound token, is refused
with `invalid_token` ({{Section 3.1 of RFC6750}}). The authorization
server authorizes a request for a Mission when:

- the access token was issued to the Mission's client, for example
  through the client credentials grant ({{Section 4.4 of RFC6749}});
  or
- its policy authorizes the access token's holder for that Mission,
  for example the resource owner, the approver, or an administrator.

Under an accepted access token, an unknown Mission Identifier and one
the caller is not authorized for both return HTTP 404, so the endpoint
does not reveal which identifiers exist.

`GET` returns HTTP 200 and a JSON object with the Mission's `id`,
`issuer`, `state`, `expires_at`, and `termination` when present. It
also returns `authorization_details` to a caller the authorization
server authorizes to read the Approved Authority.

`DELETE` ends an active Mission with termination reason `revoked` and
returns HTTP 204. A `DELETE` for a Mission that has already ended
changes nothing and returns HTTP 204.

# Resource Server Enforcement {#rs-enforcement}

For an operation it protects under this document, a resource server:

1. validates the access token, from the token itself {{RFC9068}} or
   by introspection {{RFC7662}}, including any sender constraint;
2. requires the `mission` member, and requires `mission.issuer` to
   equal the token's issuer, which it trusts to issue Mission-bound
   tokens;
3. treats the carried `authorization_details` as the authoritative
   statement of the token's authority: where several entries apply
   they are alternative grants, an entry it cannot fully enforce
   grants nothing, and it never combines parts of several entries to
   authorize one request;
4. never grants, on the basis of a `scope` value the token also
   carries, access broader than the corresponding entry permits; and
5. establishes that the Mission is active, by introspection or by the
   token's lifetime ({{lifecycle}}).

A resource server MUST refuse an access token without the `mission`
member for a Mission-governed operation; otherwise a client holding an
ordinary token for the same resource would be unaffected when the
Mission ends. It declares Mission-governed operations in its protected
resource metadata {{RFC9728}}:

`mission_grants_required`:
: A boolean. `true` declares that the resource's protected operations
  are Mission-governed. Absent means `false`.

Denials distinguish three causes, because each calls for a different
response from the client:

- the Mission has ended: `invalid_token`, with a `mission_error`
  parameter carrying the termination reason where the resource server
  knows it; the client stops the work;
- the operation is outside the carried authority:
  `insufficient_scope` ({{RFC6750}}); more authority needs a new
  Mission; and
- only the credential failed: `invalid_token`; the client can obtain
  a new token while the Mission is active.

Where more than one applies, an ended Mission takes precedence.

# Authorization Server Metadata {#metadata}

This document defines these authorization server metadata parameters
{{RFC8414}}:

`mission_grants_supported`:
: A boolean. `true` declares that the authorization server implements
  this document. Absent means `false`.

`mission_management_endpoint`:
: A URL: the management endpoint ({{management}}). REQUIRED when
  `mission_grants_supported` is `true`.

The authorization server lists the authorization details types it
accepts in a Mission request in `authorization_details_types_supported`
({{Section 10 of RFC9396}}).

# Extension Points {#extension-points}

A specification that extends Missions can:

- define an authorization request parameter that the authorization
  server records with the Mission at approval, such as a description
  of the work, as an additional record member that, like the others,
  never changes;
- define further members of the management endpoint's response;
- register lifecycle states ({{iana-states}}) and termination reasons
  ({{iana-reasons}}); and
- define, for a type of authorization details, the comparison the
  subset rule uses ({{subset}}).

No extension widens the Approved Authority, permits issuance or
reliance in any state other than `active`, or reactivates a terminated
Mission.

# Security Considerations {#security}

**The approval sets the ceiling.** The Approved Authority is fixed at
approval and the subset rule bounds every later token, so a client
cannot raise its authority by refreshing or exchanging. A narrowing
the type cannot compare is refused rather than guessed.

**Refresh token theft.** A Mission's authority lasts as long as its
refresh token can be used. For a confidential client, the
authorization server authenticates the client on refresh and verifies
that the refresh token was issued to it ({{Section 6 of RFC6749}}).
Where several users' devices can obtain the client's credentials, that
check does not separate them, and binding the refresh token to a
proof-of-possession key {{RFC9449}} does. The
security best current practice {{RFC9700}} applies.

**Acceptance after ending.** Tokens already issued outlive the ending
by up to their lifetime ({{lifecycle}}). Short access token lifetimes,
or introspection on each use, bound that interval.

**Management authority.** Ending and reading a Mission require
authorization independent of the Mission's own tokens, so a party
holding a stolen Mission-bound token cannot end or inspect the
Mission, and a party that must stop the work does not need the
client's cooperation.

**Downgrade.** Without a Mission, a client's tokens are unaffected
when the work is withdrawn. A client that requested a Mission and got
none does not use the tokens for the work ({{requesting}}), and a
resource server refuses tokens without a Mission for Mission-governed
operations ({{rs-enforcement}}).

**Scope beside authorization details.** A token that carries both
`scope` and `authorization_details` must not let the scope widen an
entry; the resource server rule of {{rs-enforcement}} prevents it.

# Privacy Considerations {#privacy}

The Mission Identifier joins every token of a Mission, so any party
that sees several of them can link them; the identifier is opaque and
carries no information about the resource owner or the work. The
`mission` claim carries only the identifier and issuer. The record
and the Approved Authority are disclosed at the management endpoint
only to authorized callers, and the endpoint's uniform 404 avoids
revealing which Missions exist.

# IANA Considerations {#iana}

The token claim, response parameters, and error member below share
their names and meanings with Mission-Bound Authorization for OAuth
2.0 {{I-D.draft-mcguinness-oauth-mission}}, which requests the same
registrations. The two documents are expected to converge on one
registration, in which that document cites this one for these names.

## OAuth Parameters {#iana-oauth-parameters}

This document requests registration of the following in the "OAuth
Parameters" registry:

| Name | Usage location | Reference |
|---|---|---|
| `mission_expires_in` | authorization request | {{requesting}} |
| `mission_id` | token response | {{token-response}} |
| `mission_expires_at` | token response | {{token-response}} |
| `mission_error` | token error response | {{gating}} |
{: title="OAuth Parameters"}

## JSON Web Token Claims {#iana-jwt}

This document requests registration of the `mission` claim in the
"JSON Web Token Claims" registry {{RFC7519}}: Claim Name `mission`, Claim
Description "Mission reference", Change Controller IETF, Reference
{{mission-claim}}.

## Token Introspection Response {#iana-introspection}

This document requests registration of `mission` in the "OAuth Token
Introspection Response" registry, with Description "Mission reference"
and Reference {{mission-claim}}.

## Authorization Server Metadata {#iana-as-metadata}

This document requests registration of `mission_grants_supported` and
`mission_management_endpoint` in the "OAuth Authorization Server
Metadata" registry, with Reference {{metadata}}.

## Protected Resource Metadata {#iana-prm}

This document requests registration of `mission_grants_required` in
the "OAuth Protected Resource Metadata" registry, with Reference
{{rs-enforcement}}.

## Mission Lifecycle States {#iana-states}

This document requests a new "Mission Lifecycle States" registry,
under Specification Required, with initial values `active` and
`terminated` ({{lifecycle}}).

## Mission Termination Reasons {#iana-reasons}

This document requests a new "Mission Termination Reasons" registry,
under Specification Required, with initial values `revoked` and
`expired` ({{lifecycle}}).

--- back

# The Bounded Work Framework's Requirements {#bounded-work-mapping}
{:numbered="false"}

This appendix is informative. It maps the requirements of the
framework for approved bounded work
{{I-D.draft-liu-mcguinness-oauth-bounded-work}} to this document.

| Requirement | Met by |
|---|---|
| R1: an identifier distinct from the client, any token, and any refresh token family | The Mission Identifier ({{record}}) |
| R2: what was approved is fixed at approval; more authority creates a new authorization | The record's fixed members and a new Mission for more authority ({{record}}). The record fixes the approved authority and the approver, not the request: it does not distinguish the authorization server's narrowing from the approver's. It records no description of the work; a specification that adds one does so through {{extension-points}}. |
| R3: no credential broader than the approved bounds, under a comparison defined for the type, refusing where it cannot decide | The subset rule ({{subset}}) |
| R4: every issuance path refuses once the authorization has ended | Issuance gating ({{gating}}) |
| R5: a party holding no token ends one authorization without affecting the client's other work | `DELETE` at the management endpoint, and a lineage per Mission ({{management}}, {{lineage}}) |
| R6: issued credentials stop being accepted within a stated time | Access token lifetime, bounded by `expires_at`, or introspection ({{lifecycle}}) |
| R7: a second party relates each credential to its authorization without inference | The `mission` claim and introspection member ({{mission-claim}}) |
| R8: an authorized second party asks whether an authorization is active | `GET` at the management endpoint ({{management}}) |
{: title="Bounded work requirements"}

The framework distinguishes four ending reasons: completed, withdrawn,
terminated, and expired. This document registers `revoked`, which
covers withdrawal and administrative ending, and `expired`; a
specification can register the others ({{iana-reasons}}). The
framework's case of work that reaches a second authorization server is
outside this document.

# Example {#example}
{:numbered="false"}

The client pushes an authorization request (line breaks for display):

~~~ http-message
POST /par HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

response_type=code
&client_id=agent-7
&redirect_uri=https%3A%2F%2Fagent.example%2Fcb
&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
&code_challenge_method=S256
&mission_expires_in=86400
&authorization_details=%5B%7B%22type%22%3A%22payment_initiation%22%2C
%22actions%22%3A%5B%22initiate%22%5D%2C%22locations%22%3A%5B
%22https%3A%2F%2Fpay.example.com%22%5D%7D%5D
&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3A
client-assertion-type%3Ajwt-bearer
&client_assertion=eyJhbGciOiJFUzI1NiJ9...
~~~

After approval and code redemption, the token response:

~~~ json
{
  "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCJ9...",
  "token_type": "DPoP",
  "expires_in": 300,
  "refresh_token": "rt_4mN8qV2xP7sL1tY9zB3k",
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

The access token's claims include:

~~~ json
{
  "iss": "https://as.example.com",
  "aud": "https://pay.example.com",
  "client_id": "agent-7",
  "exp": 1795079100,
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

A security tool ends the Mission, and the client's next refresh is
refused:

~~~ http-message
DELETE /missions/msn_K9iLTMIDFUiBucaPegc_B4lY HTTP/1.1
Host: as.example.com
Authorization: DPoP eyJhbGciOiJFUzI1NiJ9...
DPoP: eyJ0eXAiOiJkcG9wK2p3dCJ9...

HTTP/1.1 204 No Content
~~~

~~~ json
{
  "error": "invalid_grant",
  "mission_error": "revoked"
}
~~~

# Document History {#document-history}
{:numbered="false"}

\[\[ To be removed from the final specification ]]

-00

- Initial version: the Mission without a description of the work,
  built from Rich Authorization Requests and the refresh token
  lineage, with the `mission` claim, the subset rule, issuance gating,
  a lifecycle, and a management endpoint.
