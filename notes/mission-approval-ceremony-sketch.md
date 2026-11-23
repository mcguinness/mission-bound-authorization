---
title: "OAuth 2.0 Mission Approval Ceremony"
abbrev: "Mission Approval Ceremony"
category: std

docname: draft-mcguinness-oauth-mission-approval-ceremony-latest
submissiontype: IETF
workgroup: Web Authorization Protocol
number:
date:
consensus: true
v: 3
keyword:
 - oauth
 - mission
 - approval
 - consent
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-approval-ceremony.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC9068:
  RFC6749:
  RFC7636:
  RFC7662:
  RFC8414:
  RFC9207:
  RFC9396:
  RFC9449:
  OpenID.Core:
    title: "OpenID Connect Core 1.0 incorporating errata set 2"
    target: https://openid.net/specs/openid-connect-core-1_0.html
    author:
      - org: OpenID Foundation
    date: 2023
  MISSION-GRANTS:
    title: "OAuth 2.0 Mission Grants"
    target: https://github.com/mcguinness/mission-bound-authorization/blob/main/notes/mission-grants-sketch.md
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

informative:
  RFC9470:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission/
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  MISSION-INTENT:
    title: "OAuth 2.0 Mission Intent"
    target: https://github.com/mcguinness/mission-bound-authorization/blob/main/notes/mission-intent-sketch.md
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
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

--- abstract

OAuth 2.0 Mission Grants has the resource owner approve a Mission and
records the approved authority, but says little about the approval
itself. This document defines the approval ceremony as a layer on it:
who
approves and for whom, how strongly the approver authenticates, whose
authority the approval draws on and how that is checked, what the
approver is shown, and how the approval leg is protected. It records
the approver, the subject, the authority source, and the approver's
authentication with the Mission, discloses them only to authorized
parties, and adds requirements to its base without relaxing any.

--- middle

# Introduction {#introduction}

OAuth 2.0 Mission Grants {{MISSION-GRANTS}}, the Mission base this
document extends, records one approval of authorization details
{{RFC9396}} and governs every token issued under it. In it the
resource owner approves, the authorization server authenticates them,
and the Mission records the resource owner. It does not say how
strongly the approver
authenticates, lets anyone other than the resource owner approve,
records whose authority the approval draws on, or states what the
approver must be shown beyond the authority itself.

This document defines that approval ceremony as a layer on either
base:

- the approver and the subject are distinct principals, so an
  administrator can approve for a user and a workload can be the
  subject ({{principals}});
- the approver's authentication meets a published floor for high-risk
  authority and any strength the client requests ({{authentication}});
- the approval draws on an authority source the authorization server
  establishes and checks ({{sources}});
- the presentation identifies the client, the subject, and the source,
  and separates what the client asked for from what the authorization
  server changed ({{presentation}});
- a change before the decision requires consent to the changed context
  ({{changes}}), and the approval leg is protected against code
  injection and mix-up ({{leg}}); and
- the approver, the subject, the authority source, and the approver's
  achieved authentication are recorded with the Mission ({{record}})
  and disclosed only to authorized parties ({{disclosure}}), and the
  token response names the Subject ({{confirming}}).

This document grants no authority, and adds requirements to its base
without relaxing any. Its terms
Approver, Subject, and authority source, and the record members
`subject` and `authority_source`, have the meaning they have in
Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}}. A Mission created under this
document is not a Mission of that document. Where the authorization
server also implements OAuth 2.0 Mission Intent {{MISSION-INTENT}}, the
two layers compose as {{intent}} states.

## Conventions and Terminology {#terminology}

{::boilerplate bcp14-tagged}

This document uses the terms authorization server, client, resource
owner, and access token from {{RFC6749}}, and authorization details
from {{RFC9396}}.

Mission base:
: OAuth 2.0 Mission Grants {{MISSION-GRANTS}}. This document uses its
  terms Mission, Mission Record, Approved Authority, and Mission-bound
  token, and its extension points for approval by a party other than
  the resource owner, record members, token response members,
  introspection `mission` members, and management endpoint response
  members.

Principal:
: An (`iss`, `sub`) pair. Two principals are equal when both members
  are byte-equal.

Approver:
: The principal who approves the Mission and is accountable for the
  approval.

Subject:
: The principal the Mission's authority is for: the resource owner
  whose authority the tokens carry, named by the `sub` of every
  Mission-bound token.

Authority source:
: Whose authority the approval draws on ({{sources}}).

High-risk authority:
: Authority whose actions the deployment classifies as irreversible,
  external-commitment, or privileged administration, and any further
  class that a profile the authorization server implements defines.

## Reading the Base Under This Layer {#reading}

Each base has the resource owner approve, and records the resource
owner as `sub`. Under this layer, the base's statements that the
resource owner approves, is authenticated, narrows the authority, and
is presented the authority apply to the Approver. The base's `sub`
names the Subject. When the Approver is the Subject, as in every
Mission of a base without this layer, the two readings coincide. The
base's means for the resource owner to end Missions without holding a
token is also offered to the Approver.

# Principals {#principals}

The authorization server establishes the Subject at the approval:

- **Self-approval.** When the Approver is the Subject, the Subject is
  the authenticated Approver.
- **Approval for another principal.** When the Approver is a different
  principal, such as an administrator approving for a user, the
  authorization server MUST NOT take the Subject from unauthenticated
  client input, and MUST authorize the Approver to approve for that
  Subject under its policy. This document defines no wire parameter
  for the Subject; administrative selection, a directory, or an
  authenticated reference can establish it.
- **External Subject.** When the Subject's home issuer differs from the
  authorization server, the authorization server MUST map the external
  principal to a `sub` of its own under an injective mapping, so that
  no two external Subjects share one `sub`. Adopting the external `sub`
  unchanged is valid only where the authorization server reserves that
  `sub` for that external principal, so that no other principal, now or
  later, receives it.

A Mission has exactly one accountable Approver. Approval that requires
several principals is out of scope; a deployment that requires it
records one accountable Approver.

# Authenticating the Approver {#authentication}

The authorization server MUST establish the Approver's identity and
achieved authentication from the authenticated surface that resolved
the approval, never from client input.

**The floor.** A deployment MUST publish a statement of the minimum
approval-authentication strength it enforces for a Mission whose
Approved Authority carries high-risk authority, and the deployment
scope it applies to. This document requires no serialization. An
approval of such a Mission whose authentication does not meet the floor
creates no Mission.

**Requested strength.** A client MAY request an approval-authentication
strength with the `acr_values` and `max_age` parameters of Section
3.1.2.1 of {{OpenID.Core}}, which {{RFC9470}} also uses in OAuth
requests. In a Mission approval they describe the Approver's
authentication, not the Subject's, and they bind: where OpenID Connect
treats a requested `acr` as voluntary, an approval under this document
that does not meet a requested strength creates no Mission. The Approver's
authentication satisfies `acr_values` when it matches one listed value
under the deployment's policy; this document defines no ordering of
`acr` values. An approval MUST meet both the floor and any requested
strength, and a weaker or absent request never relaxes the floor.

**OpenID Connect.** An authorization request whose `scope` includes
`openid` asks for an ID Token about the Approver. When the Approver is
not the Subject, the authorization server MUST refuse such a request
with `invalid_scope`, and MUST NOT issue an ID Token, serve UserInfo,
or establish a session for the Subject as a result of the Approver's
authentication. When the Approver is the Subject, `openid` keeps its
{{OpenID.Core}} meaning, and a requested strength binds as above. In every approval, `prompt`,
`login_hint`, and `id_token_hint` concern the Approver.

The achieved authentication (`acr`, `amr`, and `auth_time`, the claims
of {{Section 2.2.1 of RFC9068}}) is recorded with the Mission as
approval-time provenance ({{record}}). Authentication claims on a
Mission-bound token describe the Subject: when the Approver is not the
Subject, the authorization server MUST NOT put the Approver's
authentication in them.

# Authority Sources {#sources}

An approval draws on one of three authority sources:

- **`user_delegated`**: a person's own authority;
- **`service_owned`**: a workload's own provisioned authority; or
- **`organizational`**: governed organizational policy with a named
  accountable owner.

The authorization server MUST establish the source from trusted
configuration or authenticated governance state, never from client
input, and then:

- MUST verify that the Approver is authorized under its policy to
  activate that source; and
- MUST verify that the Approved Authority lies within the source's
  authority, and for `organizational`, within the governed policy.

The checks are distinct: an organizational owner can be authorized to
activate a policy without holding each permission it grants. The
authorization server MUST refuse the approval when either check cannot
be established, and MUST NOT approve a Mission whose source it does not
recognize.

The Subject follows the source. Only a `user_delegated` Mission has a
person as its Subject. A `service_owned` or `organizational` Mission
MUST have the workload or organizational principal as its Subject, a
principal the authorization server recognizes as a resource owner in
its own right (the `sub` model of {{RFC9068}}), and MUST NOT name a
human in its place. The Approver is
recorded separately in every source ({{record}}) and is never inferred
from the Subject.

# Presenting the Approval {#presentation}

The Approved Authority remains the object of approval, presented as
its base requires. The presentation also:

- MUST identify the client from client identity information the
  authorization server trusts, such as its own registration of the
  client; display text the client supplies does not by itself
  identify it;
- MUST identify the Subject when the Approver is not the Subject;
- MUST identify the authority source and, for `organizational`, the
  governed policy;
- MUST distinguish the entries the client requested from any narrowing
  the authorization server applied;
- shows the Mission's expiry, and the client's requested ceiling when
  the expiry is earlier; and
- presents a statement of authority an entry carries beyond what it
  names, where the authorization server holds one (for example,
  account recovery at services that send codes to a mailbox the entry
  reads), as a disclosure of risk attributed to its source, never as
  part of the Approved Authority.

A presentation MUST NOT show a bound as enforced when no party enforces
it.

# Changes Before the Decision {#changes}

The decision binds what the presentation showed. If the Subject,
compared as its (`iss`, `sub`) pair, the requested authority, the
Approved Authority, the authority source, the Mission's expiry, or a
policy input establishing any of them changes between the
presentation and the decision, the authorization server MUST
recompute the affected values and MUST NOT create the Mission without
the Approver's consent to the changed context. The Mission records the
Subject the Approver consented to.

# Protecting the Approval Leg {#leg}

The authorization code carries the approval through the front channel.
The authorization server MUST bind it to the requesting client with
PKCE {{RFC7636}} using the `S256` method. A DPoP-bound authorization
code ({{Section 10 of RFC9449}}) can be used in addition; alone it
protects only when each authorization request uses a fresh key. The
authorization server SHOULD return the `iss` authorization response
parameter {{RFC9207}} so the client can detect a mix-up on the
approval's redirect.

# The Recorded Approval {#record}

An approval under this document records these facts with the Mission,
fixed like the base's other facts:

`approver`:
: REQUIRED. An object with `iss` and `sub`: the Approver. It equals
  `subject` for self-approval.

`subject`:
: REQUIRED. An object with `iss` and `sub`: the Subject's home issuer
  and identifier. For a Subject of the authorization server itself,
  `iss` is its issuer identifier and `sub` equals the base's `sub`; for
  an external Subject, the base's `sub` is the mapped `sub`
  ({{principals}}).

`authority_source`:
: REQUIRED. An object:

  `type`:
  : REQUIRED. A string: `user_delegated`, `service_owned`, or
    `organizational`.

  `policy`:
  : REQUIRED for `organizational`, absent otherwise. An object with
    `id`, `version`, and `digest`: a reference to the governed policy,
    and a commitment over it whose construction the policy's format
    specifies. A consumer that holds the policy can reproduce
    `digest`; one that does not compares it as an opaque string.

`approver_authentication`:
: REQUIRED. An object: the Approver's achieved authentication at the
  approval.

  `acr`:
  : REQUIRED. A string: the achieved authentication context class.

  `auth_time`:
  : REQUIRED. A number: the time of the Approver's authentication, in
    seconds since 1970-01-01T00:00:00Z.

  `amr`:
  : OPTIONAL. An array of strings: the authentication methods used.

These are members of the Mission Record.

These facts are provenance. They never grant or widen authority, and a
resource server does not consult them. A consumer preserves an
`authority_source.type` value it does not recognize as opaque
provenance, and refuses only an operation that itself requires that
source's semantics.

# Confirming the Subject {#confirming}

The token response that redeems the authorization code MUST carry:

`mission_subject`:
: An object with `iss` and `sub`: the Subject as the authorization
  server identifies it to clients. `iss` is the authorization server's
  issuer identifier, and `sub` is the base's `sub`, which for an
  external Subject is the mapped local identifier ({{principals}}). The
  Subject's home issuer and identifier stay in the recorded `subject`
  ({{record}}).

A client that began the request for a known account compares the
returned pair with the pair it holds for that account at this
authorization server, as principals ({{terminology}}). On
a mismatch, or when `mission_subject` is missing, it MUST NOT attach the
Mission to the account or use its tokens for the work, and SHOULD end
the Mission as its base provides. A client whose flow lets the Approver
choose the Subject during approval attaches the Mission to the
returned pair, never to a Subject it infers from the Approver's session
or from a token it treats as opaque.

# Disclosure {#disclosure}

No fact this document records is carried in the `mission` claim of a
JWT access token.

An introspection response {{RFC7662}} for a Mission-bound token MAY
carry `approver`, `subject`, `authority_source`, and
`approver_authentication` as members of its `mission` member, and the authorization server MUST disclose each only
to a caller it authorizes for that member. On Mission Grants, the
management endpoint's `GET` response carries them only to such a
caller.

# Composition with Mission Intent {#intent}

Where the authorization server also implements OAuth 2.0 Mission Intent
{{MISSION-INTENT}}:

- the Intent is part of the context whose change requires consent
  ({{changes}});
- the requested ceiling the presentation shows includes the Intent's
  `expires_at` ({{presentation}}); and
- the Intent's own presentation rules apply alongside these.

# Error Responses {#errors}

An approval this document refuses is reported as an authorization error
response ({{Section 4.1.2.1 of RFC6749}}):

| Condition | Error code |
|---|---|
| `openid` requested and the Approver is not the Subject | `invalid_scope` |
| The Approver declines | `access_denied` |
| Authentication misses the floor or a requested strength | `access_denied` |
| The Approver is not authorized for the Subject or the source | `access_denied` |
| The source is unrecognized, or the authority exceeds it | `access_denied` |
{: title="Approval refusals"}

No refused approval creates a Mission or an authorization code.

# Authorization Server Metadata {#metadata}

This document defines one authorization server metadata parameter
{{RFC8414}}:

`mission_approval_ceremony_supported`:
: A boolean. `true` declares that the authorization server implements
  this document. Absent means
  `false`.

# Security Considerations {#security}

**Observability.** A client cannot observe whether the floor was
enforced at the approval. A party authorized to read the recorded
approval ({{disclosure}}) can: it sees who approved, for whom, under
which source, and with what achieved authentication, and can compare
that with the published floor.

**Confused principals.** Separating the Approver from the Subject
prevents an administrator's approval from becoming the user's
authentication: no ID Token, UserInfo response, or session for the
Subject follows from it ({{authentication}}).

**Subject substitution.** The decision binds the Subject the
presentation identified, so an Approver authorized for several
Subjects cannot be shown one while the Mission records another
({{changes}}).

**Client-asserted standing.** The Subject and the authority source come
from authenticated state, never from the client, so a client cannot
name a more powerful Subject or source than the Approver is authorized
for ({{principals}}, {{sources}}).

**Authority withdrawn after approval.** Withdrawing the Approver's
authority over the Subject, or the governed policy, does not by itself
end a Mission. A deployment that requires that ends the Mission through
its base.

**Spoofed presentation.** The client is identified from information the
authorization server trusts, so a client cannot present itself as
another ({{presentation}}).

**No change to authority.** The recorded approval is provenance, so the
base's issuance and enforcement guarantees hold unchanged.

# Privacy Considerations {#privacy}

The recorded `approver` and `subject` identify people or workloads and
persist with the Mission. The authorization server discloses them only
to callers it authorizes for them ({{disclosure}}). When the Approver
is not the Subject, the Subject's identity reaches the Approver through
the presentation, which the authorization of the Approver for that
Subject already permits.

# IANA Considerations {#iana}

This document requests registration of:

- `mission_approval_ceremony_supported` in the "OAuth Authorization
  Server Metadata" registry, Reference {{metadata}}; and
- `mission_subject` in the "OAuth Parameters" registry, usage location
  token response, Reference {{confirming}}.

The `approver`, `subject`, `authority_source`, and
`approver_authentication` members of the introspection `mission`
member need no registration.

--- back

# The Bounded Work Framework's Requirements {#bounded-work-mapping}
{:numbered="false"}

This appendix is informative. The framework for approved bounded work
{{I-D.draft-liu-mcguinness-oauth-bounded-work}} requires that what was
approved, including who approved it, is fixed (R2). The base records
the resource owner who approved and leaves an accountable approver
other than the resource owner to an extension. With this document the
record also fixes the accountable Approver, the Subject, and the
authority source. The other requirements are met as the base meets
them.

# Example {#example}
{:numbered="false"}

On Mission Grants, an administrator approves a Mission for a user. The
client pushes the Mission request with a requested strength (line
breaks for display):

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
&authorization_details=...
&acr_values=phr
&max_age=300
&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3A
client-assertion-type%3Ajwt-bearer
&client_assertion=eyJhbGciOiJFUzI1NiJ9...
~~~

The administrator authenticates at `phr` within the last five minutes,
meeting the request and the deployment's floor. The authorization
server establishes the Subject from its directory, establishes the
`user_delegated` source, verifies the administrator may approve for
that user, and presents the authority with the client's registered
name and the user's identity. An auditor authorized for the recorded
approval reads the Mission:

~~~ json
{
  "id": "msn_K9iLTMIDFUiBucaPegc_B4lY",
  "issuer": "https://as.example.com",
  "state": "active",
  "expires_at": "2026-12-01T00:00:00Z",
  "approver": {
    "iss": "https://as.example.com",
    "sub": "admin_Q4vR8tLm"
  },
  "subject": {
    "iss": "https://as.example.com",
    "sub": "user_5Tn8qW2xK7mR4vBc"
  },
  "authority_source": { "type": "user_delegated" },
  "approver_authentication": {
    "acr": "phr",
    "auth_time": 1795996680
  }
}
~~~

When the Subject is federated, the two pairs differ. For a user whose
home issuer is `https://idp.partner.example`, the token response
carries the local pair the client knows the account by:

~~~ json
{
  "mission_subject": {
    "iss": "https://as.example.com",
    "sub": "fed_7Hq2Lm9Xc4Rt"
  }
}
~~~

The recorded approval keeps the home pair:

~~~ json
{
  "subject": {
    "iss": "https://idp.partner.example",
    "sub": "8f3e2a71-c0d9"
  }
}
~~~

# Document History {#document-history}
{:numbered="false"}

\[\[ To be removed from the final specification ]]

-00

- Initial version: the approval ceremony layered on a Mission base,
  with the Approver and Subject distinct, the authentication floor and
  requested strength, authority sources, presentation, and the recorded
  approval.
