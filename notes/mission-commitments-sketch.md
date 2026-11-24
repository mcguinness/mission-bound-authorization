---
title: "OAuth 2.0 Mission Commitments"
abbrev: "Mission Commitments"
category: std

docname: draft-mcguinness-oauth-mission-commitments-latest
submissiontype: IETF
workgroup: Web Authorization Protocol
number:
date:
consensus: true
v: 3
keyword:
 - oauth
 - mission
 - commitment
 - integrity
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-commitments.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC4648:
  RFC6234:
  RFC6920:
  RFC7493:
  RFC7519:
  RFC7662:
  RFC8414:
  RFC8785:
  RFC9396:
  MISSION-GRANTS:
    title: "OAuth 2.0 Mission Grants"
    target: https://github.com/mcguinness/mission-bound-authorization/blob/main/notes/mission-grants-sketch.md
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

informative:
  RFC6749:
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
  MISSION-APPROVAL-CEREMONY:
    title: "OAuth 2.0 Mission Approval Ceremony"
    target: https://github.com/mcguinness/mission-bound-authorization/blob/main/notes/mission-approval-ceremony-sketch.md
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

OAuth 2.0 Mission Grants fixes what was approved but gives no way to
check it later or to cite it compactly. This document defines
commitments as a layer on it: one construction for a domain-separated, issuer-bound
digest of a JSON object; an authority commitment over a Mission's
approved authority; an entry commitment that cites one approved entry;
and an approval event identifier that keeps one approval from creating
two Missions. Other layers commit their own objects with the same
construction. The commitments are provenance, disclosed only to
authorized parties, and add requirements to the base without relaxing
any.

--- middle

# Introduction {#introduction}

OAuth 2.0 Mission Grants {{MISSION-GRANTS}}, the Mission base this
document extends, records one approval of authorization details
{{RFC9396}} and governs every token issued under it. It fixes the
Approved Authority when the Mission is created, but gives no party a compact value to check the
approved authority against, a way to cite one approved entry, or an
identifier for the approval event itself.

This document adds those as a layer on the base:

- a commitment construction: a digest over a JSON object, separated by
  object type and bound to the authorization server's issuer
  ({{construction}});
- `authority_hash`, the authority commitment over the Approved
  Authority ({{authority-commitment}});
- the entry commitment, which cites one approved entry
  ({{entry-commitment}});
- `approval_event_id`, which identifies the approval event and keeps a
  retried approval from creating a second Mission ({{approval-event}});
  and
- the rules other specifications follow to define further commitments
  ({{other-commitments}}).

The commitments are provenance and grant no authority. This document
adds requirements to its base and relaxes none. The construction, its `typ` values, and the members
`authority_hash` and `approval_event_id` have the meaning they have in
Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}}, and produce the same bytes for
the same inputs. A Mission created under this document is not a Mission
of that document.

## Conventions and Terminology {#terminology}

{::boilerplate bcp14-tagged}

This document uses the terms authorization server and client from
{{RFC6749}}, and authorization details from {{RFC9396}}.

Mission base:
: OAuth 2.0 Mission Grants {{MISSION-GRANTS}}. This document uses its
  terms Mission, Mission Identifier, Mission Record, Approved
  Authority, and Mission-bound token, and its extension points for
  record members, introspection `mission` members, and management
  endpoint response members.

Commitment:
: A prefixed string, such as `sha-256:` followed by an encoded digest,
  that commits to exactly one byte sequence.

Anchor:
: A commitment made with the envelope construction of
  {{construction}}.

# The Commitment Construction {#construction}

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
another. The prefix names the algorithm ({{algorithm}}).

## Canonicalization {#canonicalization}

JCS alone leaves gaps that two implementations could fill differently.
These rules close them, for computing an anchor and for comparing
committed values:

- The committed `value` is exactly the object the authorization server
  recorded, so an auditor reproduces the anchor from the record alone.
- JCS does not reorder arrays, and this document defines no sorting, so
  array order is significant. The authorization server presents each
  committed array in its recorded order wherever it emits it.
- URI values are committed and compared byte for byte, with no
  normalization, unless a type defines a normalization for a
  comparison of its own; anchor computation is always byte-exact over
  the recorded values.

## Input and Algorithm {#algorithm}

Every committed value and its envelope are I-JSON {{RFC7493}} data, as
{{Section 3.1 of RFC8785}} requires. The party computing or verifying
a commitment MUST reject input that is not I-JSON rather than adapt
it, and MUST parse received JSON with a parser that rejects duplicate
member names. The commitment is over the parsed data, not the source
text, so a value that needs exact decimal or large-integer semantics
is carried as a string. An authorization server MUST refuse
`authorization_details` that is not I-JSON, or that has duplicate member
names, with `invalid_authorization_details` ({{RFC9396}}), so that what
it records can be committed.

`sha-256` is mandatory to implement and the only algorithm this
document defines. A new algorithm enters only through a new prefix
that a referencing specification defines, named from the Named
Information Hash Algorithm Registry {{RFC6920}}; there is no
negotiation. A verifier MUST reject a commitment whose prefix it does
not recognize, so a later algorithm cannot be used to downgrade.

# The Authority Commitment {#authority-commitment}

`authority_hash` is the anchor with `typ` `mission-authority-set` and
`value` the Approved Authority, as the JSON array of entries the
Mission records. The authorization server computes it when the
approval decision commits, and it is fixed with the Mission like the
base's other facts:

`authority_hash`:
: OPTIONAL. A string: the authority commitment. A Mission that does not
  record it has an implied value: the anchor computed over its recorded
  Approved Authority, with `iss` the Mission's issuer.

An authorization server that emits or verifies a Mission's
`authority_hash` MUST resolve it, recorded or implied, from the
Mission's recorded Approved Authority: never from the subset a token
carries, a projection it serves, or authority narrowed after approval.

`authority_hash` commits authority, not a Mission. Two Missions that
approve byte-identical authority share it, so a party MUST NOT use it
as a Mission Identifier or as a replay or idempotency key.

# The Entry Commitment {#entry-commitment}

The entry commitment is the anchor with `typ` `mission-authority-entry`,
`iss` the Mission's issuer, and `value` one entry of the Approved
Authority exactly as recorded. A specification that cites an approved
entry by digest, such as a decision record naming the entry it
evaluated, computes it this way.

Entries with identical canonical envelopes have the same entry
commitment, and within one Mission they are one entry for every
purpose that selects by it. Because the envelope binds the issuer and
not the Mission, a protocol that uses the entry commitment to select or
cite an entry MUST also bind the Mission's issuer and Mission
Identifier, directly or through an integrity-protected object that
carries them.

# The Approval Event {#approval-event}

`approval_event_id` identifies the approval event that created a
Mission. It is fixed with the Mission:

`approval_event_id`:
: REQUIRED. A string, unique among the authorization server's
  Missions: the identifier of the approval event that created this
  Mission.

It is the approval's idempotency key: the authorization server
recognizes a retried or duplicate delivery of one approval decision,
such as a replayed callback or a double-submitted consent form, by it,
and answers as its base requires, with the outcome of the first
decision and never a second Mission or authorization code
({{MISSION-GRANTS}}).

The authorization server:

- MUST allocate `approval_event_id` itself, and MUST NOT derive it from
  a value a client supplies or can reuse;
- MUST allocate it before the decision commits and bind it to the
  approval interaction, never to a `request_uri` or another value the
  client supplies; and
- MUST NOT create a Mission from a decision delivered after the
  interaction's lifetime, and retains the identifier for at least that
  lifetime.

# Other Commitments {#other-commitments}

A specification can commit other objects with the construction of
{{construction}}. It defines a new `typ` value, which MUST be a
Collision-Resistant Name ({{Section 2 of RFC7519}}); values with the
`mission-` prefix are coordinated among the documents that use this
construction. There is no registry of `typ` values.

A commitment can take one of three forms, and a specification that
defines one states which:

- **Anchor**: the envelope construction of {{construction}}.
- **Canonical-object digest**: the `sha-256:` digest of the JCS form of
  a JSON object without the envelope, where the protocol context
  already fixes what is committed.
- **Raw-octet digest**: the `sha-256:` digest of an exact octet
  sequence the specification defines, such as an artifact as
  exchanged.

{{algorithm}} binds all three forms, and its I-JSON rule binds the two
JSON forms. A specification that introduces a new algorithm prefix
defines where a parallel commitment is carried, how the old and new
values are shown to commit to the same object, producer and verifier
behavior while both are in use, and the transition. It never changes a
commitment already made, including an implied value.

# Disclosure {#disclosure}

No commitment this document defines is carried in the `mission` claim
of a JWT access token: a resource server enforces the authorization
details a token carries, not the Approved Authority as a whole.

An introspection response {{RFC7662}} for a Mission-bound token MAY
carry `authority_hash` and `approval_event_id` as members of its
`mission` member, and the authorization server MUST disclose each only
to a caller it authorizes for that member. On Mission Grants, the
management endpoint's `GET` response carries them only to such a
caller. A party that holds the Mission's recorded Approved Authority
verifies `authority_hash` by recomputing it.

# Composition with Other Layers {#composition}

- **OAuth 2.0 Mission Intent** {{MISSION-INTENT}}: its `intent_hash`
  is the anchor of {{construction}} with `typ` `mission-intent` over the
  approved Intent, which that document restates for that one object.
  Where both documents are implemented, `authority_hash`
  ({{authority-commitment}}) commits the authority beside the Intent.
- **OAuth 2.0 Mission Approval Ceremony** {{MISSION-APPROVAL-CEREMONY}}:
  the `digest` of an organizational `authority_source.policy` is a
  commitment in one of the forms of {{other-commitments}}. Its issuer
  is the policy's governing authority, not the authorization server,
  so the same policy commits identically wherever it is recorded.
- A layer that roots a Mission in an earlier approval, such as standing
  consent, refers to that approval through `approval_event_id` and to
  its consented authority through `authority_hash`.

# Authorization Server Metadata {#metadata}

This document defines one authorization server metadata parameter
{{RFC8414}}:

`mission_commitments_supported`:
: A boolean. `true` declares that the authorization server implements
  this document. Absent means
  `false`.

# Security Considerations {#security}

**What a commitment proves.** An anchor proves that a recorded object
is the one committed. It does not prove that the authority serves the
task, that the approval was proper, or that the Mission is active.

**Domain separation and transplant.** The `typ` member keeps a digest
of one kind of object from standing for another, and the `iss` member
keeps a commitment from verifying at another authorization server.

**Canonicalization.** Rejecting duplicate member names and non-I-JSON
input before canonicalization, and committing over parsed data, keeps
two parties from computing different digests for what they believe is
the same object ({{algorithm}}).

**Algorithm downgrade.** A verifier rejects an unknown prefix, and no
negotiation exists, so a weaker algorithm cannot be substituted.

**Not an identifier.** `authority_hash` and the entry commitment repeat
across Missions with identical content ({{authority-commitment}},
{{entry-commitment}}). `approval_event_id` is the identifier that keeps
a replayed approval from creating a second Mission ({{approval-event}}).

# Privacy Considerations {#privacy}

The anchors are unsalted: a party that holds or guesses a candidate
object can confirm it against the commitment, so over low-entropy
authority an anchor discloses it. The authorization server discloses
each commitment only to a caller authorized for it ({{disclosure}}).
`approval_event_id` and `authority_hash` let a party that sees several
of them correlate Missions; the same disclosure rule bounds that.

# IANA Considerations {#iana}

This document requests registration of `mission_commitments_supported`
in the "OAuth Authorization Server Metadata" registry, Reference
{{metadata}}.

The `authority_hash` and `approval_event_id` members of the
introspection `mission` member need no registration, and this document
defines no registry of `typ` values ({{other-commitments}}).

--- back

# The Bounded Work Framework's Requirements {#bounded-work-mapping}
{:numbered="false"}

This appendix is informative. The framework for approved bounded work
{{I-D.draft-liu-mcguinness-oauth-bounded-work}} requires that what was
approved is fixed (R2) and that a second party can relate a credential
to its authorization (R7). The base meets both. With this document, an
auditor can also verify the fixed authority against `authority_hash`,
and a record can cite one approved entry by its entry commitment. The
other requirements are met as the base meets them.

# Test Vectors {#test-vectors}
{:numbered="false"}

These vectors let an implementation check its construction byte for
byte. All use the issuer `https://as.example.com`. Each canonical-bytes block is
one line of JCS output, wrapped here for layout only: removing the line
breaks, and adding nothing, recovers it. JCS sorts member names and
keeps array order.

`authority_hash`, over this Approved Authority:

~~~ json
[
  { "type": "payment_initiation",
    "actions": ["initiate", "status"],
    "locations": ["https://pay.example.com"],
    "instructedAmount": { "currency": "EUR", "amount": "123.50" } },
  { "type": "account_information",
    "actions": ["read"],
    "locations": ["https://bank.example.com"] }
]
~~~

Canonical bytes of the envelope:

~~~ text
{"iss":"https://as.example.com","typ":"mission-authority-set","val
ue":[{"actions":["initiate","status"],"instructedAmount":{"amount"
:"123.50","currency":"EUR"},"locations":["https://pay.example.com"
],"type":"payment_initiation"},{"actions":["read"],"locations":["h
ttps://bank.example.com"],"type":"account_information"}]}
~~~

~~~ text
authority_hash = sha-256:l28eepFYHmeoPsJG4KFJKkuRXBIoBkTFZ9LyObcZ_GA
~~~

The same two entries in the opposite order commit differently, since
array order is significant:

~~~ text
authority_hash = sha-256:E69LywJT-8huema6dMmzsOmKp-dkDjBl1JkJXEY2lXI
~~~

The entry commitment, over the second entry:

~~~ text
{"iss":"https://as.example.com","typ":"mission-authority-entry","v
alue":{"actions":["read"],"locations":["https://bank.example.com"]
,"type":"account_information"}}
~~~

~~~ text
entry_commitment =
  sha-256:ux5wiHfA9kf19LqMASpI4oRUiK-LogZ5twwjKC95WXE
~~~

# Document History {#document-history}
{:numbered="false"}

\[\[ To be removed from the final specification ]]

-00

- Initial version: the commitment construction, the authority and entry
  commitments, and the approval event identifier, layered on a Mission
  base.
