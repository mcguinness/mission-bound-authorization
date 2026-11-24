---
title: "OAuth 2.0 Mission"
abbrev: "OAuth Mission"
category: std

docname: draft-mcguinness-oauth-mission-base-latest
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
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-base.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC3339:
  RFC4648:
  RFC6234:
  RFC6749:
  RFC6750:
  RFC7009:
  RFC6920:
  RFC7493:
  RFC7519:
  RFC7662:
  RFC8259:
  RFC8414:
  RFC8693:
  RFC8707:
  RFC8785:
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
gated on the Mission's state, a lifecycle, and a Mission Record endpoint.
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
records a description of the task and adds further mechanisms. The
token claim and response parameters this document shares with it have
the same meaning; `mission_error` is narrower here, reporting only an
ended Mission, with `mission_refusal` for a refusal while a Mission
continues.

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

Approval decision:
: The authorization server's decision on a Mission request: to create
  the Mission, or to refuse ({{approval}}).

Mission request:
: A request that asks the authorization server to create a Mission:
  an authorization request that carries `mission_expires_in`
  ({{requesting}}), or the request a creation path defines
  ({{creation-paths}}).

Approved Authority:
: The `authorization_details` array the approval established for a
  Mission.

Mission grant lineage:
: The grant that created a Mission (the authorization code, or the
  grant a creation path defines; {{creation-paths}}) and the refresh
  tokens issued from it.

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
2. The resource owner approves; the authorization server creates the
   Mission ({{approval}}).
3. and 4. The client redeems the authorization code.
5. The token response carries the Mission Identifier and expiry
   ({{token-response}}).
6. and 7. The resource server checks the token, the Mission's state,
   and the operation against the carried authority ({{rs-enforcement}}).
8. Refresh, and any other issuance under the Mission, succeeds only
   while the Mission is active ({{gating}}).

At any time, an authorized party can end the Mission or read its state
at the Mission Record endpoint ({{management}}).

# Requesting a Mission {#requesting}

This document defines the following authorization request parameter:

`mission_expires_in`:
: A positive integer: the requested maximum lifetime of the Mission,
  in seconds from approval. Its presence requests a Mission.

An authorization request that carries `mission_expires_in` MUST also
carry `authorization_details` {{RFC9396}}. The authorization server
MUST refuse an authorization request that carries `mission_expires_in`
without
`authorization_details`, or with a value that is not a positive
integer, with the `invalid_request` error code. A client SHOULD send
the request as a Pushed Authorization Request {{RFC9126}}. The request
can also carry `scope`, as {{Section 3.1 of RFC9396}} allows, but a
Mission-bound access token conveys no authority through it
({{subset}}).

A client learns that it will not get a Mission from the absence of
`mission_supported` ({{metadata}}) before it sends the request,
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
policy, and the resource owner MAY narrow it further. Each entry of the
Approved Authority MUST be of the same type as a requested entry and
MUST grant no more than that entry; an entry is never widened and
entries are never combined. Before approval, the authorization server
presents the authority it will approve, as it will be granted, in
terms the resource owner can understand.

The resource owner approves, and the authorization server
authenticates them. A specification can define approval by another
party, such as an administrator approving for the resource owner,
together with the record member that names that party. It can also
define approval with no person at the decision, such as by an
organizational policy; such a specification states what replaces the
presentation and the authentication above, and records what decided
({{extension-points}}). An approval decision creates the Mission and the
grant that starts its lineage together: on the path this document
defines, the authorization code, which the authorization server issues
only when the Mission is recorded. A declined or abandoned request
creates neither. A retried or duplicate delivery of one approval
decision MUST receive the outcome of the first, the same response or
the same refusal, and MUST NOT create a second Mission or yield a
second grant that starts a Mission grant lineage.

## Other Creation Paths {#creation-paths}

A specification can define another path that creates a Mission, such
as a backchannel or device authorization flow, a deferred approval, or
the activation of a standing approval. Such a path:

- creates the Mission atomically with the grant it issues, which
  starts the Mission's grant lineage ({{lineage}});
- carries the client's requested lifetime, as `mission_expires_in` or
  an equivalent the path defines, and the requested authority, as
  `authorization_details` or by reference to a standing approval that
  states it;
- establishes the Approved Authority as {{approval}} requires, under
  the approval model it or another specification defines; and
- issues tokens under the Mission only as this document does, with the
  token response members ({{token-response}}), the subset rule
  ({{subset}}), and issuance gating ({{gating}}).

A standing approval that authorizes later activations is not itself a
Mission: each activation is its own approval decision under this
document and creates one Mission, which the specification defining the
standing approval relates to it.

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
: REQUIRED. A string: the resource owner the Mission is for, as the
  authorization server identifies them. The resource owner approves
  the Mission unless a specification defines approval by another party
  ({{extension-points}}).

`approved_at`:
: REQUIRED. A string: an RFC 3339 {{RFC3339}} date-time, the instant
  of approval.

`expires_at`:
: REQUIRED. A string: an RFC 3339 date-time set by the authorization
  server. It MUST be later than `approved_at` and MUST NOT be later
  than `approved_at` plus the requested lifetime (`mission_expires_in`,
  or the equivalent a creation path defines).

`authorization_details`:
: REQUIRED. The Approved Authority.

`state`:
: REQUIRED. A string: the Mission's lifecycle state, `active` or
  `terminated`, or a state a specification registers ({{lifecycle}}).

`termination`:
: Present exactly when `state` is `terminated`. An object:

  `reason`:
  : REQUIRED. A string: why the Mission ended, a value of the OAuth
    Mission Termination Reasons registry ({{iana-reasons}}): `revoked`
    or `expired` in this document, or a reason a specification
    registers.

  `terminated_at`:
  : REQUIRED. A string: the RFC 3339 instant the termination took
    effect; for `expired`, the Mission's `expires_at`.

  A specification that registers a termination reason can define
  further members of `termination` for it.

`extensions`:
: OPTIONAL. An array of strings: the extensions that apply to this
  Mission, each a value of the OAuth Mission Extensions registry
  ({{iana-extensions}}). Absent means none.

`state` changes only as {{lifecycle}} allows. The authorization
server writes `termination` once, together with the transition to
`terminated`, and MUST NOT change it: a later event does not replace
the reason of a Mission already terminated. A member another
specification defines to record an ending is written with
`termination`, and one it defines for a state it registers is written
on entering that state and holds only while the Mission is in it
({{extension-points}}). Every other member, including members another
specification defines, is fixed when the Mission is created and never
changes.
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

The token response that first issues tokens under a Mission,
redeeming its authorization code or the grant a creation path defines,
MUST carry a refresh token, so that the client can always end its Mission
({{lifecycle}}), and, besides the tokens and the granted
`authorization_details` ({{Section 7 of RFC9396}}):

`mission_id`:
: A string: the Mission Identifier. It is a reference only; presenting
  it authorizes nothing.

`mission_expires_at`:
: The exact RFC 3339 string of the Mission's `expires_at`. The
  `expires_in` parameter describes the access token's lifetime, not
  the Mission's.

`mission_extensions`:
: The Mission's `extensions` ({{record}}), when it has any.

Any other token response under a Mission SHOULD carry `mission_id`
and `mission_expires_at`, and `mission_extensions` when the Mission has
any.

## Mission Grant Lineage {#lineage}

The grant that created a Mission, and every refresh token issued from
it, belong to that Mission and to no other.
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

The `mission` claim and the introspection `mission` member are open
objects: a consumer ignores a member it does not understand, and no
member grants or widens authority.

## The Subset Rule {#subset}

Every access token the authorization server issues under a Mission,
and every token that carries a Mission to another issuer
({{other-issuers}}), has an audience: the resource the request names with `resource`
({{RFC8707}}), or with `resource` or `audience` at Token Exchange
({{RFC8693}}), or, where the request names none, one the authorization
server assigns. Each entry of the token's `authorization_details` MUST
meet three conditions:

1. **Within the bound.** It is an entry of the bound carried
   unchanged, or a narrowing of one such entry under a comparison that
   the entry's type defines, and it never combines rights from several
   entries. At the first issuance and at refresh, the bound is the
   Approved Authority: a refresh can ask for any authority the Mission's grant
   lineage holds, as a refresh under {{Section 6 of RFC6749}} can ask
   for any scope originally granted. At Token Exchange, the bound is
   the subject token's `authorization_details`, so an exchange never
   restores authority the subject token does not carry, and a chain of
   exchanges only narrows.
2. **Within the request.** Where the request carries
   `authorization_details`, the entry is a requested entry or a
   narrowing of one; an entry broader than the requested one is never
   issued in its place.
3. **For the audience.** The entry applies to every audience of the
   token: its `locations` ({{Section 2.2 of RFC9396}}) include the
   audience value, compared as strings, or its type defines how it
   applies to that audience, or, for a token that carries the Mission
   to another issuer, the issuer relationship defines how it applies
   to that issuer ({{other-issuers}}). An entry with none of these
   applies nowhere.

Where the request carries no `authorization_details`, the
authorization server issues the entries of the bound that apply to the
audience, unchanged. The authorization server MUST refuse a request
that carries `authorization_details` with the
`invalid_authorization_details` error code ({{Section 6 of RFC9396}})
when a requested entry fails a condition, or needs a comparison that
the entry's type does not define or that cannot decide it; and MUST
refuse a request that carries none with `invalid_target`
({{Section 2 of RFC8707}}) when no entry of the bound applies to the
audience. The Mission Resource Access Profile
{{I-D.draft-mcguinness-oauth-mission-resource-access}} is an example of
a type specification that defines a comparison. This document defines
no way to discover which narrowings an authorization server accepts; a
client that needs one learns from the refusal.

A Mission-bound access token carries no `scope`, in the token or in an
introspection response, unless a specification that bounds `scope` by
the Approved Authority applies ({{extension-points}}). A `scope` value
requested with a Mission, such as `openid`, keeps its own meaning
outside the Mission and conveys no authority through a Mission-bound
token.

## Token Exchange {#exchange}

A client exchanges a Mission-bound access token for another with a
Token Exchange request ({{Section 2.1 of RFC8693}}) whose
`subject_token` is that access token, with `subject_token_type`
`urn:ietf:params:oauth:token-type:access_token`. Only the Mission's
client exchanges, unless a specification defines delegation
({{delegation-exchange}}), and only a subject token it shows it holds:

- a refresh token is never a subject token;
- for a sender-constrained subject token, the request's proof of
  possession MUST use the key the subject token is bound to; for DPoP,
  the request's DPoP proof is signed with that key, which {{RFC9449}}
  alone does not require; and
- for a subject token that is not sender-constrained, the client MUST
  authenticate as a confidential client, so a public client exchanges
  only sender-constrained subject tokens.

The issued token is an access token (the response's
`issued_token_type` is `urn:ietf:params:oauth:token-type:access_token`),
except the token an issuer relationship defines ({{other-issuers}}).
It carries the same `mission` claim, meets the subset rule
({{subset}}), has an expiry no later than the subject token's, is bound
to the key of the request's proof of possession where there is one,
and is gated on the same Mission ({{gating}}). The authorization server
MUST refuse, with `invalid_request`, an exchange whose
`requested_token_type` names another token type, except as an issuer
relationship defines ({{other-issuers}}), and MUST NOT include a
`refresh_token` in its response, although {{Section 2.2.1 of RFC8693}}
permits one: the Mission's grant lineage ({{lineage}}) is its only
refresh path.

The authorization server first applies its token endpoint's own
checks, with their own error codes: client authentication
(`invalid_client`, {{Section 5.2 of RFC6749}}) and, where DPoP is used,
the proof's validity, including any nonce it requires
(`invalid_dpop_proof`, or `use_dpop_nonce` with a `DPoP-Nonce` header,
{{Section 8 of RFC9449}}). It then MUST check the exchange in this
order, and MUST refuse it at the first failure with `invalid_request`
({{Section 2.2.2 of RFC8693}}) unless a step names another code:

1. that the client is the Mission's client: by its authentication, or,
   for a public client, by the `client_id` it presents together with
   the proof of the subject token's key, which only the Mission's client
   received;
2. that the subject token is a Mission-bound access token the
   authorization server issued, by its signature or its own record;
3. that the client holds the subject token, as above;
4. issuance gating ({{gating}}), which refuses with `mission_error`
   when the Mission has ended, including when it has expired, and with
   `mission_refusal` when it has not;
5. that the subject token itself is still valid: not revoked on its
   own, not expired, and meeting any other condition the authorization
   server applies to it; and
6. the subset rule ({{subset}}), with its own error codes.

Only an exchange that passes the token endpoint's checks and steps 1
to 3 can receive `mission_error` or `mission_refusal`, so a party that cannot show it holds
the subject token learns nothing about the Mission. Step 4 precedes
step 5, so a Mission that has ended takes precedence over the token's
own expiry or revocation, including when the token expires with its
Mission. A token revoked on its own under an active Mission is refused
at step 5, with `invalid_request` and no `mission_error`.

### Delegation {#delegation-exchange}

A specification that defines delegation can admit a party other than
the Mission's client to exchange, for example a delegate that presents
an `actor_token` ({{Section 2.1 of RFC8693}}). It states which parties
it admits, how each shows that it holds what it presents, in place of
the holder rules listed above and steps 1 and 3, so that no party
exchanges a token it cannot show it holds, and how the issued token
identifies the party,
for example in the `act` claim. It does not relax any other rule of
this section: the subject token is an access token, the issued token's
expiry is no later than the subject token's, no refresh token is
issued, and the subset rule and issuance gating apply.

### Other Issuers {#other-issuers}

A specification can define a relationship under which an issuer other
than the Mission's issues tokens for it, such as an authorization
server in another trust domain. It defines the token the Mission's
issuer issues by exchange to carry the Mission to that issuer, which
can be of another token type, and when an entry of the Approved
Authority applies to that issuer for the subset rule. The Mission's
issuer MUST report that token as active, at introspection, only while
the Mission is active. The specification defines how the other issuer
redeems the token, in place of this section's exchange rules, and MUST
require that the other issuer:

- issues tokens only to a party that shows it holds the carrying
  token, as the specification defines;
- issues only access tokens, each carrying the same `mission` claim,
  meeting the subset rule against the carrying token, expiring no
  later than it, and bound to the key of the redeeming party's proof
  of possession where there is one;
- issues no refresh token under the Mission;
- issues nothing unless the Mission is active at the instant of
  issuance, which it confirms as the specification defines, such as
  by introspecting the carrying token at the Mission's issuer, so that
  issuance gating ({{gating}}) holds at every issuer; and
- reports a token it issued as active, at introspection, only while
  the Mission is active.

A resource server accepts such a token only under that relationship
({{rs-enforcement}}).

## Issuance Gating {#gating}

The authorization server MUST NOT issue a token under a Mission, at
any issuance path, unless the Mission is `active` at the instant of
issuance. It refuses a first issuance or a refresh under a Mission
that is not active with `invalid_grant` ({{Section 5.2 of RFC6749}}),
and a Token Exchange whose subject token's Mission is not active with
`invalid_request` ({{Section 2.2.2 of RFC8693}}). When the Mission is
`terminated`, it adds this member to either error response:

`mission_error`:
: A string: the Mission's termination reason ({{record}}).

The authorization server MUST NOT add `mission_error` for a Mission
that is not terminated. A client that receives `mission_error`, with
any value, including one it does not recognize, stops the work and
does not seek another credential for it: the Mission has ended, and no
retry under it succeeds.

When the authorization server refuses an issuance under a Mission that
has not ended because of the Mission rather than the request, either
because the Mission is in a state another specification registers or
because of a condition of the Mission as a whole that another
specification defines, such as an exhausted budget, it refuses with the
error code above for that path, and MUST add this member in place of
`mission_error`:

`mission_refusal`:
: A string: why the issuance is refused while the Mission continues, a
  value of the OAuth Mission Refusal Reasons registry
  ({{iana-refusals}}). For a refusal because of the Mission's state, it
  is the name of that state.

A refusal because of what the request asks for, such as an audience
or authority outside a bound, carries the error code its rule names and
neither member.

A refusal with `mission_refusal` leaves a presented refresh token
usable: it does not rotate or revoke it, or count as its reuse. An
authorization code is used once ({{Section 4.1.2 of RFC6749}}), so a
first issuance refused this way leaves the Mission without a grant,
and the Mission ends at its `expires_at` or when an authorized party
ends it. A client that receives
`mission_refusal`, with any value, including one it does not
recognize, keeps its grant, does not treat the Mission as ended, and
retries only as the value's specification allows.

At the first issuance and at refresh, the authorization server
validates the grant as {{RFC6749}} or the creation path requires
before it applies this gate, and at Token Exchange it follows the
order of {{exchange}}. It returns `mission_error` or `mission_refusal`
only to a request that passes the checks preceding this gate: the grant's validation at
the first issuance and at refresh, and the
token endpoint's checks and steps 1 to 3 at Token Exchange.

# Lifecycle {#lifecycle}

A Mission is `active` from approval and `terminated`, with a reason,
once it ends ({{record}}); other specifications can register states
between the two:

- `active`: the only state in which the authorization server issues
  tokens under it and a resource server relies on it.
- `terminated`: a terminal state. Its `termination.reason` says why
  the Mission ended: `revoked` when an authorized party ended it, or
  `expired` when its `expires_at` passed.

| From | Event | To | Reason |
|---|---|---|---|
| (none) | approval | `active` | |
| not `terminated` | revocation | `terminated` | `revoked` |
| not `terminated` | `expires_at` reached | `terminated` | `expired` |
{: title="Mission lifecycle"}

Revocation and expiry end a Mission from any state other than
`terminated`, including a state another specification registers.

A Mission is revoked when an authorized party ends it at the
Mission Record endpoint ({{management}}), or when its grant lineage is
revoked: the client revoking a refresh token of the lineage
{{RFC7009}}, or the authorization server revoking the lineage, for
example on detecting refresh token replay. So a client ends its own
Mission by revoking its refresh token, and the authorization server
MUST offer revocation of a lineage's refresh tokens at a
`revocation_endpoint` it advertises ({{RFC8414}}). Rotation, which replaces a
refresh token with another of the same lineage, is not revocation.

Separating the ending from its reason lets other specifications
extend the lifecycle without changing this document:

- a specification that defines a further way a Mission ends, such as
  completion of the work, withdrawal by the approver, or supersession,
  registers a termination reason ({{iana-reasons}}), and the Mission
  is `terminated` with that reason; and
- a specification that defines a lifecycle a Mission can return from,
  such as a pause, registers a state ({{iana-states}}). A Mission in
  such a state is neither active nor terminated, and is never reported
  with a termination reason or `mission_error`; a refusal in it carries
  `mission_refusal` ({{gating}}). A specification that registers a
  state also registers a refusal value of the same name
  ({{iana-refusals}}).

A party that learns a Mission's state MUST treat every state other
than `active`, including one it does not recognize, as permitting no issuance or reliance, and MUST
treat `terminated`, with any reason, including one it does not
recognize, as an ended Mission.

Ending a Mission stops issuance at once. An access token already
issued remains acceptable to a resource server that relies on the
token alone until the token's `exp`; a resource server that
introspects each use sees the ending at its next introspection. The
interval in which an ended Mission's tokens can still be accepted is
therefore bounded by access token lifetime, which the authorization
server SHOULD keep short. Ending a Mission does not undo effects
already accepted.

# Mission Record Endpoint {#management}

An authorization server that implements this document offers a
Mission Record endpoint, which it advertises as
`mission_record_endpoint` ({{metadata}}). Each Mission has a URL at
the endpoint, at which `GET` and `DELETE` act: the endpoint URL
followed by `/` and the Mission Identifier as a path segment.

A request for an access token for the endpoint is not a Mission
request. The token's audience is the endpoint URL, which the request
names with `resource` ({{RFC8707}}); it authorizes `GET` only when it
carries the scope value `mission:read`, and `DELETE` only when it
carries `mission:end`, in addition to the authorization below.

Every request to the endpoint carries an access token issued for the
endpoint, presented as {{RFC6750}} or, for a DPoP-bound token,
{{RFC9449}} describes. A missing or invalid access token, or one not
issued for the endpoint, such as a Mission-bound token, is refused
with `invalid_token` ({{Section 3.1 of RFC6750}}). The authorization
server MUST authorize each operation separately, reading a Mission
(`GET`) and ending it (`DELETE`); authorization to read never implies
authorization to end. It MUST NOT authorize an operation on a Mission
unless:

- **Client-wide.** The access token was issued to the Mission's client
  acting for itself, with no resource owner, for example through the
  client credentials grant ({{Section 4.4 of RFC6749}}), and the
  authorization server has explicitly granted that client the
  operation on its own Missions, for example in its registration.
  Being the Mission's client is not by itself such a grant.
- **Delegated.** For any other access token, including one issued to
  the Mission's client on behalf of a user, its policy authorizes the
  token's subject, such as the Mission's resource owner or an
  administrator, for that operation on that particular Mission. A
  token issued to the client for one user authorizes nothing on
  another user's Missions.

Under an accepted access token, an unknown Mission Identifier and one
the caller is not authorized for both return HTTP 404, so the endpoint
does not reveal which identifiers exist.

`GET` returns HTTP 200 and a JSON object with the Mission's `id`,
`issuer`, `state`, `expires_at`, its `extensions` when it has any,
and, for a terminated Mission, `termination`. It
also returns `authorization_details` to a caller the authorization
server authorizes to read the Approved Authority.

`DELETE` moves a Mission that has not ended to `terminated` with
reason `revoked` and returns HTTP 204. A `DELETE` for a Mission that has already ended
changes nothing and returns HTTP 204.

# Disclosure of Mission Facts {#disclosure}

The `id` and `issuer` of a Mission are references that any party
holding one of its tokens can see. The authorization server MUST
disclose any other fact of a Mission, whether this document or another
specification defines it, through introspection {{RFC7662}} or the
Mission Record endpoint ({{management}}), only to a caller it
authenticates and authorizes for that fact, and gives a resource server
only the `authorization_details` entries that apply to it
({{subset}}). A fact another specification defines serves audit and
correlation, and a resource server derives no authority from it, unless
that specification says otherwise.

A member another specification adds to the JWT `mission` claim reaches
every audience of the token, so such a specification adds only a
member that every audience may see.

# Resource Server Enforcement {#rs-enforcement}

For an operation it protects under this document, a resource server:

1. validates the access token, from the token itself {{RFC9068}} or
   by introspection {{RFC7662}}, including any sender constraint;
2. requires the `mission` member, and requires `mission.issuer` to
   equal the token's issuer, which it trusts to issue Mission-bound
   tokens, unless a specification defines a relationship under which
   another issuer mints tokens for a Mission, such as across trust
   domains, and the resource server trusts the token's issuer under it;
3. treats the carried `authorization_details` as the authoritative
   statement of the token's authority, using only the entries that apply
   to it ({{subset}}): where several entries apply
   they are alternative grants, an entry it cannot fully enforce
   grants nothing, and it never combines parts of several entries to
   authorize one request;
4. grants nothing, for a Mission-governed operation, on the basis of
   a `scope` value the token carries; and
5. relies on the Mission's state in one of two ways ({{lifecycle}}):
   it introspects the token at use, and an active response shows that
   the Mission is active at that instant; or it accepts a JWT until its
   `exp`, and so may accept it for up to that time after the Mission
   ends.

A resource server MUST refuse an access token without the `mission`
member for a Mission-governed operation; otherwise a client holding an
ordinary token for the same resource would be unaffected when the
Mission ends. It refuses with `invalid_token` and the
`resource_metadata` parameter ({{Section 5.1 of RFC9728}}), and
declares Mission-governed operations in that protected resource
metadata:

`mission_required`:
: A boolean. `true` declares that the resource's protected operations
  are Mission-governed. Absent means `false`.

A client that receives that refusal for a token without `mission`
obtains a Mission-bound token, rather than another of the same kind.

Denials distinguish four causes, because each calls for a different
response from the client:

- the Mission has ended: `invalid_token`, with a `mission_error`
  parameter carrying the Mission's termination reason where the
  resource server knows it; the client confirms the Mission's state at the
  authorization server, for example by a refresh, and then stops the
  work, since a resource server's `mission_error` alone is advisory;
- the Mission is in a state another specification registers:
  `invalid_token`, with a `mission_refusal` parameter carrying that
  state's name where the resource server knows it; the client keeps
  its grant and acts on the state only as the authorization server
  reports it ({{gating}});
- the operation is outside the carried authority:
  `insufficient_scope` ({{RFC6750}}); the client obtains a token for
  the operation by refresh or exchange where the Approved Authority
  covers it, and otherwise needs a new Mission; and
- only the credential failed: `invalid_token`; the client can obtain
  a new token while the Mission is active.

Where more than one applies, an ended Mission takes precedence. An
inactive introspection response does not tell a resource server
whether the credential or the Mission ended
({{Section 2.2 of RFC7662}}); it then responds `invalid_token` without
`mission_error`.

# Authorization Server Metadata {#metadata}

This document defines these authorization server metadata parameters
{{RFC8414}}:

`mission_supported`:
: A boolean. `true` declares that the authorization server implements
  this document. Absent means `false`.

`mission_record_endpoint`:
: A URL: the Mission Record endpoint ({{management}}). REQUIRED when
  `mission_supported` is `true`.

The authorization server lists the authorization details types it
accepts in a Mission request in `authorization_details_types_supported`
({{Section 10 of RFC9396}}).

# Anchors {#anchors}

This document computes no anchor, and an authorization server that
implements only this document computes none. It defines one
construction so that specifications that commit Mission facts produce
the same bytes for the same inputs; an authorization server implements
it only when a specification it implements uses it.

An anchor over a JSON value is computed as follows:

1. Construct the envelope, where `typ` names the kind of object
   committed, `iss` is the issuer identifier of the authorization
   server that makes the commitment, and `value` is the object:

   ~~~
   { "typ": "<object type>", "iss": "<issuer>", "value": <object> }
   ~~~

2. Canonicalize the envelope with JCS {{RFC8785}}.
3. Compute SHA-256 {{RFC6234}} over the canonical bytes.
4. Encode the result as `sha-256:` followed by the base64url encoding
   of the digest, without padding ({{RFC4648}}).

The `typ` value separates object types, so a digest of one kind of
object cannot stand for another. The `iss` binding keeps a committed
object from being transplanted from one authorization server to
another. A specification that commits an object defines its `typ`
value, which MUST be a Collision-Resistant Name
({{Section 2 of RFC7519}}); values with the `mission-` prefix are
coordinated among the documents that use this construction, and there
is no registry of `typ` values.

## Canonicalization {#canonicalization}

JCS alone leaves gaps that two implementations could fill differently.
These rules close them, for computing an anchor and for comparing
committed values:

- The committed `value` is exactly the object the authorization server
  recorded, so an auditor reproduces the anchor from the record alone.
- JCS does not reorder arrays, and no sorting is defined, so array
  order is significant. The authorization server presents each
  committed array in its recorded order wherever it emits it.
- URI values are committed and compared byte for byte, with no
  normalization, unless a type defines a normalization for a
  comparison of its own; anchor computation is always byte-exact over
  the recorded values.

## Input and Algorithm {#algorithm}

Every committed value and its envelope are I-JSON {{RFC7493}} data, as
{{Section 3.1 of RFC8785}} requires. The party computing or verifying
an anchor MUST reject input that is not I-JSON rather than adapt it,
and MUST parse received JSON with a parser that rejects duplicate
member names. The anchor is over the parsed data, not the source text,
so a value that needs exact decimal or large-integer semantics is
carried as a string.

`sha-256` is mandatory to implement for a party that computes anchors,
and is the only algorithm defined. A new algorithm enters only through
a new prefix that a referencing specification defines, named from the
Named Information Hash Algorithm Registry {{RFC6920}}, and there is no
negotiation. A verifier MUST reject an anchor whose prefix it does not
recognize, so a later algorithm cannot be used to downgrade. A
specification that introduces a new prefix defines where a parallel
anchor is carried, how the old and new values are shown to commit to
the same object, producer and verifier behavior while both are in use,
and the transition; it never changes an anchor already made, including
an implied value.

# Extension Points {#extension-points}

A specification that extends Missions can:

- define approval by a party other than the resource owner, with the
  record member that names that party, including approval with no
  person at the decision ({{approval}});
- define another path that creates a Mission, including the activation
  of a standing approval ({{creation-paths}});
- define delegation, admitting parties other than the Mission's client
  to exchange ({{delegation-exchange}});
- define a relationship under which an issuer other than the Mission's
  issues tokens for it ({{other-issuers}});
- define an authorization request parameter that the authorization
  server records with the Mission at approval, such as a description
  of the work, as an additional record member;
- define further members of the Mission Record that the authorization
  server writes when it creates the Mission, when it terminates it, or,
  for a state the specification registers, while the Mission is in
  that state ({{record}});
- define further operations at the Mission Record endpoint, each with
  the scope value that authorizes it, such as reporting completion or
  suspending a Mission, and further members of its responses, of the
  token response, and of the introspection `mission` member;
- define further members of the JWT `mission` claim, which every
  audience of the token sees ({{disclosure}});
- define how `scope` is bounded by the Approved Authority, so that a
  Mission-bound token can carry it;
- register termination reasons for further ways a Mission ends, and
  states for lifecycles a Mission returns from ({{lifecycle}});
- register refusal values for an issuance a specification refuses while
  the Mission continues ({{gating}}); and
- define, for a type of authorization details, the comparison the
  subset rule uses ({{subset}}).

An authorization server's metadata shows which extensions it
implements, through the members each extension's specification
defines; a Mission's `extensions` shows which of them apply to that
Mission. A specification whose extension applies to some Missions and
not others, such as one whose request parameter a client can omit,
registers an identifier ({{iana-extensions}}), and its extension
applies to a Mission only when the authorization server lists that
identifier in the Mission's `extensions` when it creates the Mission. A
client that relies on such an extension for a Mission confirms that
`mission_extensions` lists it, and otherwise does not rely on it for
that Mission, since an authorization server that does not implement the
extension can ignore what the client sent for it and still create the
Mission.

A specification registers the names of the members it adds in the
OAuth Mission Members registry ({{iana-members}}), so independent
specifications do not collide.

No extension widens the Approved Authority, permits issuance or
reliance in any state other than `active`, or reactivates an ended
Mission.

# Security Considerations {#security}

**The approval sets the ceiling.** The Approved Authority is fixed at
approval and the subset rule bounds every later token: a refresh by
the Approved Authority, and an exchange by the subject token, the
request, and the audience. A client cannot raise its authority by
refreshing past the approval, or recover authority by exchanging a
narrowed token. A narrowing
the type cannot compare is refused rather than guessed.

**Copied tokens.** Only the Mission's client, or a party a delegation
specification admits, exchanges, and only for a token it shows it
holds, and an exchange issues nothing that outlives
its subject token ({{exchange}}). A token carried to another issuer is
redeemed there only by a party that shows it holds it, and what the
other issuer issues is bound to that party's key where it proves one
({{other-issuers}}). A resource server that receives a
token therefore cannot turn it into others, and because every token
carries only the entries that apply to its audience ({{subset}}), it
cannot be replayed at another resource server.

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

**Endpoint authority.** Ending and reading a Mission require
authorization independent of the Mission's own tokens, so a party
holding a stolen Mission-bound token cannot end or inspect the
Mission, and a party that must stop the work does not need the
client's cooperation. Each operation is authorized on its own, and a
client's identity alone authorizes neither: in a multi-user client,
one user's endpoint token reaches only the Missions its subject is
authorized for ({{management}}).

**Downgrade.** Without a Mission, a client's tokens are unaffected
when the work is withdrawn. A client that requested a Mission and got
none does not use the tokens for the work ({{requesting}}), and a
resource server refuses tokens without a Mission for Mission-governed
operations ({{rs-enforcement}}).

**Scope.** A Mission-bound access token carries no `scope`, and a
resource server grants nothing for a Mission-governed operation on the
basis of one, so `scope` cannot carry authority the approval did not
({{subset}}, {{rs-enforcement}}).

# Privacy Considerations {#privacy}

The Mission Identifier joins every token of a Mission, so any party
that sees several of them can link them; the identifier is opaque and
carries no information about the resource owner or the work. The
`mission` claim carries the identifier and issuer, and only such
further members as another specification adds for every audience of
the token ({{disclosure}}). The record
and the Approved Authority are disclosed at the Mission Record endpoint
only to authorized callers, and the endpoint's uniform 404 avoids
revealing which Missions exist.

# IANA Considerations {#iana}

The token claim, response parameters, and `mission_error` below share
their names with Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}}, which requests the same
registrations; `mission_error` is narrower here ({{gating}}). The two
documents are expected to converge on one registration.

## OAuth Parameters {#iana-oauth-parameters}

This document requests registration of the following in the "OAuth
Parameters" registry:

| Name | Usage location | Reference |
|---|---|---|
| `mission_expires_in` | authorization request | {{requesting}} |
| `mission_id` | token response | {{token-response}} |
| `mission_expires_at` | token response | {{token-response}} |
| `mission_error` | token response | {{gating}} |
| `mission_refusal` | token response | {{gating}} |
| `mission_extensions` | token response | {{token-response}} |
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

This document requests registration of `mission_supported` and
`mission_record_endpoint` in the "OAuth Authorization Server
Metadata" registry, with Reference {{metadata}}.

## Protected Resource Metadata {#iana-prm}

This document requests registration of `mission_required` in
the "OAuth Protected Resource Metadata" registry, with Reference
{{rs-enforcement}}.

## OAuth Mission States {#iana-states}

This document requests a new "OAuth Mission States" registry, under
Specification Required, with initial values `active` and `terminated`
({{lifecycle}}). A state registered later is one a Mission can return
to `active` from; {{lifecycle}} says how a party treats every state
other than `active`.

## OAuth Mission Termination Reasons {#iana-reasons}

This document requests a new "OAuth Mission Termination Reasons"
registry, under Specification Required, with initial values `revoked`
and `expired` ({{lifecycle}}). Each registration names the event that
ends a Mission with that reason.

## OAuth Mission Members {#iana-members}

This document requests a new "OAuth Mission Members" registry, under
Specification Required, for the names of members of the Mission
Record and its `termination` object, of the `mission` claim and
introspection member, and of the Mission Record endpoint's responses. Each registration gives the name,
where it appears, and the specification that defines it; a name means
one thing wherever it appears. The initial values, all defined in
{{record}}, are `id` and `issuer` (record, claim, introspection,
endpoint); `expires_at`, `authorization_details`, `state`,
`termination`, and `extensions` (record, endpoint); `client_id`,
`sub`, and `approved_at` (record); and `reason` and `terminated_at`
(`termination`).

## OAuth Mission Extensions {#iana-extensions}

This document requests a new "OAuth Mission Extensions" registry,
under Specification Required, with no initial values. Each
registration gives a short identifier and the specification that
defines the extension.

## OAuth Mission Refusal Reasons {#iana-refusals}

This document requests a new "OAuth Mission Refusal Reasons" registry,
under Specification Required, with no initial values. Each
registration names the condition under which an issuance is refused
while the Mission continues, and what lifts it. A state registered in
the OAuth Mission States registry is also registered here under the
same name.

--- back

# The Bounded Work Framework's Requirements {#bounded-work-mapping}
{:numbered="false"}

This appendix is informative. It maps the requirements of the
framework for approved bounded work
{{I-D.draft-liu-mcguinness-oauth-bounded-work}} to this document.

| Requirement | Met by |
|---|---|
| R1: an identifier distinct from the client, any token, and any refresh token family | The Mission Identifier ({{record}}) |
| R2: what was approved is fixed at approval; more authority creates a new authorization | The record's fixed members and a new Mission for more authority ({{record}}). The record fixes the approved authority and the resource owner the Mission is for (`sub`), not the request: it does not distinguish the authorization server's narrowing from the resource owner's. An accountable approver other than the resource owner, and a description of the work, are left to specifications that add them through {{extension-points}}. |
| R3: no credential broader than the approved bounds, under a comparison defined for the type, refusing where it cannot decide | The subset rule at every issuance path: the bound (the Approved Authority at code redemption and refresh, the subject token at exchange), the request, and the audience ({{subset}}) |
| R4: every issuance path refuses once the authorization has ended | Issuance gating on every path; the grant lineage is the only refresh path, since an exchange issues no refresh token ({{gating}}, {{exchange}}) |
| R5: a party holding no token ends one authorization without affecting the client's other work | `DELETE` at the Mission Record endpoint, and a lineage per Mission ({{management}}, {{lineage}}) |
| R6: issued credentials stop being accepted within a stated time | Access token lifetime, bounded by `expires_at`, or introspection ({{lifecycle}}) |
| R7: a second party relates each credential to its authorization without inference | The `mission` claim and introspection member ({{mission-claim}}) |
| R8: an authorized second party asks whether an authorization is active | `GET` at the Mission Record endpoint ({{management}}) |
{: title="Bounded work requirements"}

The framework distinguishes four ending reasons: completed, withdrawn,
terminated, and expired. This document defines the termination
reasons `revoked`, which covers withdrawal and administrative ending,
and `expired`; a specification can register reasons for the others
({{iana-reasons}}), and every party still reads a Mission terminated
for a reason it does not recognize as ended. The
framework's case of work that reaches a second authorization server is
left to a specification that defines an issuer relationship
({{other-issuers}}).

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
&resource=https%3A%2F%2Fpay.example.com
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
  lineage, with the `mission` claim, the subset rule, Token Exchange,
  issuance gating and refusal signals, a lifecycle, a Mission Record
  endpoint, one disclosure rule, an anchor construction for layers that
  commit Mission facts, and extension points with registries for
  states, termination and refusal reasons, members, and extensions.
