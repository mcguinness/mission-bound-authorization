---
title: "OAuth 2.0 Mission Intent"
abbrev: "Mission Intent"
category: std

docname: draft-mcguinness-oauth-mission-intent-latest
submissiontype: IETF
workgroup: Web Authorization Protocol
number:
date:
consensus: true
v: 3
keyword:
 - oauth
 - mission
 - intent
 - rar
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-intent.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC6749:
  RFC7009:
  RFC7662:
  RFC8414:
  RFC9126:
  RFC9396:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission/
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  MISSION-GRANTS:
    title: "OAuth 2.0 Mission Grants"
    target: https://github.com/mcguinness/mission-bound-authorization/blob/main/notes/mission-grants-sketch.md
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  MISSION-TOKENS:
    title: "OAuth 2.0 Mission Tokens"
    target: https://github.com/mcguinness/mission-bound-authorization/blob/main/notes/mission-tokens-sketch.md
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

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

--- abstract

A Mission base, such as OAuth 2.0 Mission Grants or OAuth 2.0 Mission
Tokens, records one approval of authorization details and governs the
tokens issued under it, but records nothing about the work the
authority is for. This document adds a Mission Intent, a
client-authored description of the task, to either base. The client
submits the Intent with the base's Mission request; the authorization
server presents it to the resource owner beside the authority, bounds
the approved authority's resources and lifetime by it, records it with
the Mission under an integrity anchor, and confirms in the token
response that it was bound. The Intent describes and narrows; it never
supplies authority, and token issuance and resource server enforcement
are the base's, unchanged.

--- middle

# Introduction {#introduction}

A Mission base records one approval of authorization details
{{RFC9396}} as a Mission and governs every token issued under it:
OAuth 2.0 Mission Grants {{MISSION-GRANTS}} through a refresh token
lineage and a management endpoint, and OAuth 2.0 Mission Tokens
{{MISSION-TOKENS}} through one mission token used with Token Exchange,
introspection, and revocation. Either base records what was approved.
Neither records what the work is.

This document adds that description, a Mission Intent, to either base:

- the client submits the Intent with the base's Mission request
  ({{request}});
- the Intent bounds the approved authority's resources and the
  Mission's lifetime ({{ceiling}});
- the authorization server presents the Intent to the resource owner
  beside the authority it will approve ({{approval}});
- the Intent and the approved authority are recorded with the Mission,
  each under an integrity anchor ({{record}}); and
- the token response confirms that the Intent was bound
  ({{confirming}}).

The Intent describes and narrows; it never supplies authority. The
approved authority still comes only from the `authorization_details`
the client requested, and token issuance, the subset rule, issuance
gating, and resource server enforcement are the base's, unchanged.
What this document records reaches a resource server only through
introspection, to a caller the authorization server authorizes
({{disclosure}}).

The Mission Intent, the Submission envelope that carries it, and the
integrity anchors are those of Mission-Bound Authorization for OAuth
2.0 {{I-D.draft-mcguinness-oauth-mission}}, which this document cites
for their definitions. A Mission created under this document is not a
Mission of that document: it has its base's record, lifecycle, and
tokens. The names it shares with that document have the same meaning.

## Conventions and Terminology {#terminology}

{::boilerplate bcp14-tagged}

This document uses the terms authorization server, client, resource
owner, and access token from {{RFC6749}}, and authorization details
from {{RFC9396}}.

Mission base:
: OAuth 2.0 Mission Grants {{MISSION-GRANTS}} or OAuth 2.0 Mission
  Tokens {{MISSION-TOKENS}}. This document uses its terms Mission,
  Mission Identifier, Approved Authority, and Mission-bound token.

Mission request:
: The base's authorization request for a Mission: for Mission Grants,
  one carrying `mission_expires_in`; for Mission Tokens, one whose only
  `resource` is the authorization server's issuer identifier. An
  authorization server implements one base ({{bases}}).

Mission Intent:
: The JSON object describing the task, with the members `goal`,
  `goal_lang`, `target_resources`, `task_bounds`, `purpose`, and
  `expires_at`, as the "Mission Intent" section of
  {{I-D.draft-mcguinness-oauth-mission}} defines it.

Submission envelope:
: The JSON object that carries a Mission Intent as its `intent`
  member, with optional Intent Submission Evidence as its `evidence`
  member, as the "Submitting a Mission Intent" section of
  {{I-D.draft-mcguinness-oauth-mission}} defines it.

Intent-bound Mission:
: A Mission created under this document.

## Relationship to the Bases {#bases}

| | Mission Grants | Mission Tokens |
|---|---|---|
| Mission request | `mission_expires_in` | `resource` naming the authorization server |
| Lifetime bound | earlier of `mission_expires_in` and `expires_at` | `expires_at` |
| Recorded facts | Mission Record members | Mission facts |
| Read by identifier | management endpoint | none |
| Ending on a mismatch | revoke the refresh token | revoke the mission token |
{: title="This document on each base"}

# Requesting an Intent-Bound Mission {#request}

A client requests an Intent-bound Mission by adding the `mission_intent`
parameter to its base's Mission request. The parameter carries a
Submission envelope, and the request also carries
`authorization_details`. The client MUST send the request as a Pushed
Authorization Request {{RFC9126}}, in either form the "Carriage Through
PAR" section of {{I-D.draft-mcguinness-oauth-mission}} allows, and MUST
NOT send `mission_intent` as a front-channel authorization request
parameter.

The authorization server applies the rules of
{{I-D.draft-mcguinness-oauth-mission}} for the Submission envelope and
the Mission Intent: closed top levels, bounded sizes, member
validation, and the processing of Intent Submission Evidence, under
which an evidence entry that does not verify is refused. Where those
rules refer to deriving authority through a configured mapping, they
do not apply: under this document, authority comes only from the
requested `authorization_details`.

The authorization server MUST refuse, with `invalid_request`, a
request that carries `mission_intent` but is not a Mission request of
a base it implements, or that carries no `authorization_details`.

## The Intent Ceiling {#ceiling}

The Intent bounds the authority a Mission can approve:

- **Resources.** Each requested entry, and each entry of the Approved
  Authority, MUST name only resources among the Intent's
  `target_resources`, compared by exact string equality. An entry names
  a resource through each value of its `locations` member
  ({{Section 2.2 of RFC9396}}) and through any member its type defines
  as naming a resource. The authorization server refuses a request
  with an entry that names any other resource with `invalid_request`.
  An entry that names no resource is not bounded by `target_resources`.
- **Lifetime.** The Mission's expiry MUST NOT be later than the
  Intent's `expires_at`, in addition to any bound its base sets. An
  approval decision made after `expires_at` creates no Mission.

The ceiling applies at approval. Tokens issued later are bounded by
the base's subset rule against the Approved Authority, which the
ceiling already bounds.

# Approval {#approval}

The authority remains what the resource owner approves. The base's
requirement to present the authority as it will be granted applies
unchanged, and an approval presentation that shows the Intent without
that authority does not conform. In addition, the authorization
server:

- presents the Intent's `goal`, and its `task_bounds` when present,
  beside the authority, as text the client supplied: rendered as inert
  text, never interpreted as markup, visually distinct from the
  authority, and attributed to the client;
- SHOULD mitigate Unicode direction-override and confusable-character
  presentation in that text; and
- uses `goal_lang`, when present, to render it.

The Intent's prose bounds authority only through disclosure: the
resource owner can decline authority the words do not support, and the
authorization server can narrow it under policy. The authorization
server does not interpret the prose. `purpose` follows its definition
in {{I-D.draft-mcguinness-oauth-mission}}: it can contribute only to a
refusal or stricter treatment.

# The Recorded Intent {#record}

An approval decision for an Intent-bound Mission records these facts
with the Mission. Like the base's other facts, they are fixed when the
Mission is created:

`intent`:
: The approved Mission Intent: the Submission envelope's `intent`
  member, exactly as submitted.

`intent_hash`:
: The integrity anchor over `intent`, with `typ` `mission-intent`.

`authority_hash`:
: The integrity anchor over the Approved Authority, as a JSON array of
  entries, with `typ` `mission-authority-set`.

`submission_evidence`:
: Present only when the Submission envelope carried evidence: the
  verified Intent Submission Evidence facts, as
  {{I-D.draft-mcguinness-oauth-mission}} defines them.

Both anchors are computed as the "Integrity Anchors" section of
{{I-D.draft-mcguinness-oauth-mission}} defines, with `iss` the
Mission's issuer. For Mission Grants these are members of the Mission
Record; for Mission Tokens they are facts of the Mission.

# Confirming the Intent {#confirming}

An authorization server that implements only the base can ignore
`mission_intent` as an unrecognized parameter and still create a
Mission, so a Mission's existence does not show that its Intent was
bound. The token response that redeems the authorization code for an
Intent-bound Mission carries:

`mission_intent_hash`:
: A string: the Mission's `intent_hash`.

The client computes the anchor over the Intent it submitted, with the
authorization server's issuer identifier, and compares. A client that
submitted an Intent and receives a token response without
`mission_intent_hash`, or with a different value, MUST NOT use the
issued tokens for the work, and SHOULD end the Mission as its base
provides ({{bases}}), through revocation {{RFC7009}}.

# Disclosure {#disclosure}

No fact this document records is carried in the `mission` claim of a
JWT access token. A Mission Tokens exchange copies that claim into
every token it issues, and no resource server enforces these facts.

An introspection response {{RFC7662}} for a Mission-bound token MAY
carry `intent_hash` and `authority_hash` as members of its `mission`
member. The authorization server MUST disclose each only to a caller
it authorizes for that member. They serve audit and correlation, not
enforcement: a resource server never derives authority from them.

On Mission Grants, the management endpoint's `GET` response MAY carry
`intent_hash`, and carries `intent` only to a caller the authorization
server authorizes to read it. Mission Tokens defines no read by Mission
Identifier, so on that base a party reads these facts only by
introspecting a Mission-bound token it holds.

# Authorization Server Metadata {#metadata}

This document defines one authorization server metadata parameter
{{RFC8414}}:

`mission_intent_supported`:
: A boolean. `true` declares that the authorization server implements
  this document for its Mission base. Absent means
  `false`.

A client sends `mission_intent` only to an authorization server that
advertises it, and still confirms each Mission ({{confirming}}).

# Security Considerations {#security}

**The Intent is not authority.** Before approval the Intent is
untrusted client input, and after approval it is a record of what the
client said the work is. The authority is the requested
`authorization_details`, narrowed and approved. Nothing in the Intent
widens it, and the ceiling ({{ceiling}}) only narrows it.

**Goal and authority can disagree.** The authorization server does
not check that the authority serves the goal; nothing can. A client
can describe one task and request authority for another. The approval
presentation counters this by making the authority the object of
approval and attributing the goal to the client ({{approval}}).

**Downgrade.** An authorization server that ignores `mission_intent`
creates a Mission whose record lacks the Intent. The confirmation
member ({{confirming}}) lets the client detect this before any work.

**Transplant.** Each anchor binds the authorization server's issuer
identifier, so a committed Intent or authority from one authorization
server does not verify at another.

**No new issuance path.** This document changes no token request,
response rule, or enforcement rule of the base, so the base's
security properties for issuance and enforcement hold unchanged.

# Privacy Considerations {#privacy}

The Intent's prose (`goal`, `task_bounds`) persists with the Mission
and can carry personal data about the resource owner or third parties.
The authorization server discloses `intent` only to callers it
authorizes to read it.

The anchors are unsalted: a party that holds a candidate Intent can
confirm it against `intent_hash`, and over guessable content the
anchor discloses the Intent. The authorization server therefore
discloses each anchor only to a caller authorized for it
({{disclosure}}).

# IANA Considerations {#iana}

This document requests registration of:

- `mission_intent` in the "OAuth Parameters" registry, usage location
  authorization request, Reference {{request}}.
  {{I-D.draft-mcguinness-oauth-mission}} requests the same
  registration with the same meaning, and the documents are expected
  to converge on one registration;
- `mission_intent_hash` in the "OAuth Parameters" registry, usage
  location token response, Reference {{confirming}}; and
- `mission_intent_supported` in the "OAuth Authorization Server
  Metadata" registry, Reference {{metadata}}.

The `intent_hash` and `authority_hash` members of the introspection
`mission` member need no registration.

--- back

# The Bounded Work Framework's Requirements {#bounded-work-mapping}
{:numbered="false"}

This appendix is informative. The framework for approved bounded work
{{I-D.draft-liu-mcguinness-oauth-bounded-work}} requires that what was
approved is fixed (R2). Each base meets R2 for the approved authority
and the resource owner who approved, and leaves the work as described
to an extension. With this document the record also fixes the work as
described, and `intent_hash` and `authority_hash` commit the task and
the authority separately. The other requirements are met as each base
meets them.

# Example {#example}
{:numbered="false"}

On Mission Tokens, the client pushes a Mission request that carries an
Intent (line breaks for display; the two values are shown decoded
below):

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
&authorization_details=...
&mission_intent=...
&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3A
client-assertion-type%3Ajwt-bearer
&client_assertion=eyJhbGciOiJFUzI1NiJ9...
~~~

The `authorization_details` value:

~~~ json
[
  {
    "type": "payment_initiation",
    "actions": ["initiate", "status"],
    "locations": ["https://pay.example.com"],
    "instructedAmount": { "currency": "EUR", "amount": "123.50" }
  }
]
~~~

The `mission_intent` value, a Submission envelope:

~~~ json
{
  "intent": {
    "goal": "Pay invoice INV-2207 and confirm the payment.",
    "target_resources": ["https://pay.example.com"],
    "task_bounds": ["One payment only"],
    "expires_at": "2026-12-01T00:00:00Z"
  }
}
~~~

The entry's only location is among `target_resources`, so the request
is within the ceiling. The resource owner approves at
2026-11-30T00:00:00Z, and the token response carries the mission token
and the confirmation:

~~~ json
{
  "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCJ9...",
  "token_type": "DPoP",
  "expires_in": 86400,
  "authorization_details": [
    {
      "type": "payment_initiation",
      "actions": ["initiate", "status"],
      "locations": ["https://pay.example.com"],
      "instructedAmount": { "currency": "EUR", "amount": "123.50" }
    }
  ],
  "mission_intent_hash":
    "sha-256:aKKuYS1p_YcBt9C3xdj8KGjf_LwW4w1pGmFiF3vnER4"
}
~~~

The client recomputes `intent_hash` over the Intent it sent, with
issuer `https://as.example.com`, and gets the same value. An auditor
the authorization server authorizes for both anchors introspects a
token issued from the mission token and receives, among other members:

~~~ json
{
  "active": true,
  "aud": "https://pay.example.com",
  "mission": {
    "id": "msn_K9iLTMIDFUiBucaPegc_B4lY",
    "issuer": "https://as.example.com",
    "intent_hash":
      "sha-256:aKKuYS1p_YcBt9C3xdj8KGjf_LwW4w1pGmFiF3vnER4",
    "authority_hash":
      "sha-256:JJ1iY5CccSnS6JnEXJcfnWk50MhdZGV1CD1FsoTIbDI"
  }
}
~~~

# Document History {#document-history}
{:numbered="false"}

\[\[ To be removed from the final specification ]]

-00

- Initial version: a Mission Intent layered on a Mission base,
  narrowing only, with the Intent's definitions cited from
  Mission-Bound Authorization for OAuth 2.0.
