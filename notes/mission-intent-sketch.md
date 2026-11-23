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
  RFC3339:
  RFC5646:
  RFC6749:
  RFC7009:
  RFC7662:
  RFC8414:
  RFC8259:
  RFC8693:
  RFC8707:
  RFC9101:
  RFC9126:
  RFC9396:
  MISSION-COMMITMENTS:
    title: "OAuth 2.0 Mission Commitments"
    target: https://github.com/mcguinness/mission-bound-authorization/blob/main/notes/mission-commitments-sketch.md
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
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission/
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

A Mission base, such as OAuth 2.0 Mission Grants or OAuth 2.0 Mission
Tokens, records one approval of authorization details and governs the
tokens issued under it, but records nothing about the work the
authority is for. This document adds a Mission Intent, a
client-authored description of the task, to either base. The client
submits the Intent with the base's Mission request; the authorization
server presents it to the resource owner beside the authority, bounds
the approved authority's resources and lifetime by it, records it with
the Mission under an integrity anchor, and confirms in the token
response that it was bound. The Intent describes and narrows and never
supplies authority, and this document adds requirements to its base
without relaxing any.

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
the client requested. This document adds requirements to its base and
relaxes none: token issuance, the subset rule, issuance gating, and
resource server enforcement are the base's.
What this document records reaches a resource server only through
introspection, to a caller the authorization server authorizes
({{disclosure}}).

This document defines the Mission Intent and the Submission envelope
with the members and meaning they have in Mission-Bound Authorization
for OAuth 2.0 {{I-D.draft-mcguinness-oauth-mission}}, and computes its
anchors as OAuth 2.0 Mission Commitments {{MISSION-COMMITMENTS}}
defines. A Mission created under this document is not a
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
: The JSON object describing the task ({{envelope}}).

Submission envelope:
: The JSON object that carries a Mission Intent, with optional
  evidence ({{envelope}}).

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
parameter to its base's Mission request, which also carries
`authorization_details`. The parameter carries a Submission envelope
({{envelope}}). The client MUST send it through a Pushed Authorization
Request {{RFC9126}}, in one of two forms:

1. the form-encoded `mission_intent` parameter of the pushed request,
   whose value is the UTF-8 JSON {{RFC8259}} serialization of the
   Submission envelope; or
2. a `mission_intent` claim, whose value is the Submission envelope
   object itself, inside a signed Request Object {{RFC9101}} that is
   pushed. When the pushed request carries a Request Object, the
   authorization server MUST refuse a `mission_intent` outside it with
   `invalid_request`.

The authorization server MUST refuse, with `invalid_request`, a
`mission_intent` on a front-channel authorization request that does not
use a pushed `request_uri`, and ignores one on the request that redeems
a `request_uri`. It MUST refuse, with `invalid_request`, a request that
carries `mission_intent` but is not a Mission request of its base, or
that carries no `authorization_details`.

## The Submission Envelope {#envelope}

The Submission envelope is a JSON object with exactly these members:

`intent`:
: REQUIRED. The Mission Intent: a JSON object describing the task.

`evidence`:
: OPTIONAL. A non-empty array of evidence entries, each a JSON object
  whose `type` member names its evidence type.

The Mission Intent has these members, with the meaning
{{I-D.draft-mcguinness-oauth-mission}} gives them:

`goal`:
: REQUIRED. A string of at most 4096 characters: the task, for
  presentation to the resource owner. The authorization server never
  interprets it.

`goal_lang`:
: OPTIONAL. A BCP 47 language tag {{RFC5646}} for `goal` and
  `task_bounds`.

`target_resources`:
: REQUIRED. A non-empty array of absolute URIs: the resources the task
  targets, which bound the approved authority ({{ceiling}}).

`task_bounds`:
: OPTIONAL. An array of strings: the client's description of limits on
  the task. It is not an enforced bound.

`purpose`:
: OPTIONAL. A URI naming the task's purpose. It can contribute only to
  a refusal or stricter treatment, and never supplies, widens, or
  relaxes authority.

`expires_at`:
: REQUIRED. An RFC 3339 {{RFC3339}} date-time: the client's ceiling on
  the Mission's lifetime ({{ceiling}}).

Both objects are closed: the authorization server MUST refuse, with
`invalid_request`, a member that neither this document nor a profile it
implements defines. It bounds the sizes of the envelope, the Intent,
and their arrays, and refuses a submission that exceeds them with
`invalid_request`.

This document defines no evidence type. The authorization server MUST
refuse a presented evidence entry whose type it does not support, or
that fails its type's verification, with the
`invalid_mission_intent_evidence` error code, which
{{I-D.draft-mcguinness-oauth-mission}} defines; an authorization
server that supports no evidence type refuses every presented entry.

## Processing Order {#processing}

After the checks its base makes on the Mission request, the
authorization server processes the Intent in this order, and MUST
refuse a request that fails more than one check with the error of the
earliest failing step:

1. parse the Submission envelope, enforce the closed members and the
   size bounds, and check that each evidence entry is an object with a
   `type` member (`invalid_request`);
2. validate the Intent's members, including a well-formed `goal_lang`
   and an `expires_at` that is well-formed and not past
   (`invalid_request`);
3. apply the Intent ceiling to the requested `authorization_details`
   ({{ceiling}}; `invalid_request`); and
4. verify each presented evidence entry
   (`invalid_mission_intent_evidence`).

The rule of {{I-D.draft-mcguinness-oauth-mission}} that treats a pushed
`resource` or `scope` as a requested subset of the authority the
Intent yields does not apply: the base governs `resource`.

## The Intent Ceiling {#ceiling}

The Intent bounds the authority a Mission can approve:

- **Resources.** Each requested entry, and each entry of the Approved
  Authority, MUST name only resources among the Intent's
  `target_resources`, compared by exact string equality. An entry names
  a resource through each value of its `locations` member
  ({{Section 2.2 of RFC9396}}) and through any member its type defines
  as naming a resource. The authorization server refuses a request
  with an entry that names any other resource, or that names no
  resource and so cannot be bounded, with `invalid_request`.
- **Lifetime.** The Mission's expiry MUST NOT be later than the
  Intent's `expires_at`, in addition to any bound its base sets. An
  approval decision made after `expires_at` creates no Mission, and the
  authorization server refuses it with `access_denied`
  ({{Section 4.1.2.1 of RFC6749}}).
- **Audiences.** The authorization server MUST NOT issue a resource
  token for an Intent-bound Mission whose audience is not among the
  recorded `target_resources`, at code redemption, refresh, or Token
  Exchange, wherever its base issues a resource token, and refuses such
  a request with `invalid_target` ({{Section 2 of RFC8707}},
  {{Section 2.2.2 of RFC8693}}). An entry whose type makes it apply to
  another audience therefore does not carry the Mission past the
  resources the resource owner was shown. The Mission Tokens mission
  token, whose audience is the authorization server, is not a resource
  token.

The resource and lifetime bounds apply at approval. The audience bound
applies at every issuance, alongside the base's subset rule against the
Approved Authority.

# Approval {#approval}

The authority remains what the resource owner approves. The base's
requirement to present the authority as it will be granted applies,
and an approval presentation that shows the Intent without that
authority does not conform. In addition, the authorization server:

- presents the Intent's `target_resources` with the authority, so the
  resource owner sees the ceiling the Intent sets ({{ceiling}});
- presents the Intent's `goal`, and its `task_bounds` when present,
  beside the authority, as text the client supplied: rendered as inert
  text, never interpreted as markup, visually distinct from the
  authority, attributed to the client, and never presented as a bound
  that a party enforces;
- SHOULD mitigate Unicode direction-override and confusable-character
  presentation in that text; and
- uses `goal_lang`, when present, to render it.

The Intent's prose bounds authority only through disclosure: the
resource owner can decline authority the words do not support, and the
authorization server can narrow it under policy. The authorization
server does not interpret the prose, and `purpose` can contribute only
to a refusal or stricter treatment ({{envelope}}).

# The Recorded Intent {#record}

An approval decision for an Intent-bound Mission records these facts
with the Mission. Like the base's other facts, they are fixed when the
Mission is created:

`intent`:
: The approved Mission Intent: the Submission envelope's `intent`
  member, exactly as submitted.

`intent_hash`:
: The anchor of {{MISSION-COMMITMENTS}} over `intent`, with `typ`
  `mission-intent`. A Mission that does not record it has the implied
  value computed over `intent`.

`authority_hash`:
: The authority commitment over the Approved Authority, as
  {{MISSION-COMMITMENTS}} defines it.

`submission_evidence`:
: Present only when the Submission envelope carried evidence: the
  verified evidence facts that the evidence type's specification
  defines.

Both anchors bind the Mission's issuer. For Mission Grants these facts
are members of the Mission Record; for Mission Tokens they are facts of
the Mission.

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

**No new issuance path.** This document adds requirements to its base
and relaxes none, so the base's security properties for issuance and
enforcement hold.

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

This document uses the `invalid_mission_intent_evidence` error code,
which {{I-D.draft-mcguinness-oauth-mission}} registers.

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
  "mission_id": "msn_K9iLTMIDFUiBucaPegc_B4lY",
  "mission_expires_at": "2026-12-01T00:00:00Z",
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
  narrowing only, with the Intent restated with the meaning
  Mission-Bound Authorization for OAuth 2.0 gives it, and anchors from
  OAuth 2.0 Mission Commitments.
