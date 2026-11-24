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
  RFC7493:
  RFC7662:
  RFC8414:
  RFC9396:
  MISSION-BASE:
    title: "OAuth 2.0 Mission"
    target: https://github.com/mcguinness/mission-bound-authorization/blob/main/notes/mission-base-sketch.md
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

OAuth 2.0 Mission fixes what was approved but gives no way to
check it later or to cite it compactly. This document defines
commitments as a layer on it, using the base's anchor construction: an
authority commitment over a Mission's
approved authority; an entry commitment that cites one approved entry;
and an approval event identifier that keeps one approval from creating
two Missions. Other layers commit their own objects with the same
construction. The commitments are provenance, disclosed only to
authorized parties, and add requirements to the base without relaxing
any.

--- middle

# Introduction {#introduction}

OAuth 2.0 Mission {{MISSION-BASE}}, the Mission base this
document extends, records one approval of authorization details
{{RFC9396}} and governs every token issued under it. It fixes the
Approved Authority when the Mission is created, but gives no party a compact value to check the
approved authority against, a way to cite one approved entry, or an
identifier for the approval event itself.

This document adds those as a layer on the base:

- the use of the base's anchor construction for the objects below
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
: OAuth 2.0 Mission {{MISSION-BASE}}. This document uses its
  terms Mission, Mission Identifier, Mission Record, Approved
  Authority, and Mission-bound token, and its extension points for
  record members, introspection `mission` members, and Mission Record
  endpoint response members.

Commitment:
: A prefixed string, such as `sha-256:` followed by an encoded digest,
  that commits to exactly one byte sequence.

Anchor:
: A commitment made with the envelope construction of
  {{construction}}.

# The Commitment Construction {#construction}

This document computes its anchors with the construction OAuth 2.0
Mission defines ({{MISSION-BASE}}, Section "Anchors"), under its
canonicalization, input, and algorithm rules. An authorization server
that implements this document MUST refuse `authorization_details` that
is not I-JSON {{RFC7493}}, or that has duplicate member names, with
`invalid_authorization_details` ({{RFC9396}}), so that what it records
can be committed.

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

Each Mission that an authorization server implementing this document
creates records `approval_event_id` ({{approval-event}}), may record
`authority_hash`, and lists `commitments` in its `extensions`
({{MISSION-BASE}}).

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
decision and never a second Mission or creating grant
({{MISSION-BASE}}).

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
{{construction}}. It defines a new `typ` value under the base's naming
rule for anchors.

A commitment can take one of three forms, and a specification that
defines one states which:

- **Anchor**: the envelope construction of {{construction}}. A
  commitment over an object governed outside the authorization server,
  such as an organizational policy, uses the issuer that the object's
  format defines, so the object commits identically wherever it is
  recorded.
- **Canonical-object digest**: the `sha-256:` digest of the JCS form of
  a JSON object without the envelope, where the protocol context
  already fixes what is committed.
- **Raw-octet digest**: the `sha-256:` digest of an exact octet
  sequence the specification defines, such as an artifact as
  exchanged.

The base's input and algorithm rules bind all three forms, including
its rules for a new algorithm prefix, and its I-JSON rule binds the two
JSON forms ({{construction}}).

# Disclosure {#disclosure}

No commitment this document defines is carried in the `mission` claim
of a JWT access token: a resource server enforces the authorization
details a token carries, not the Approved Authority as a whole.

An introspection response {{RFC7662}} for a Mission-bound token MAY
carry `authority_hash` and `approval_event_id` as members of its
`mission` member, and the Mission Record endpoint's `GET` response MAY
carry them, each under the base's rule for disclosing Mission facts
({{MISSION-BASE}}). A party that holds the Mission's recorded Approved Authority
verifies `authority_hash` by recomputing it.

# Use by Other Layers {#composition}

Another layer commits the objects it records with the construction of
{{construction}}, under its own `typ` ({{other-commitments}}). A layer
that roots a Mission in an earlier approval, such as standing consent,
refers to that approval through `approval_event_id` and to its
consented authority through `authority_hash`.

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
the same object ({{construction}}).

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
{{metadata}}, and of `commitments` in the "OAuth Mission Extensions"
registry, Reference {{authority-commitment}}.

This document requests registration of `authority_hash` and
`approval_event_id` in the "OAuth Mission Members" registry
({{MISSION-BASE}}), as Mission Record members that also appear in the
introspection `mission` member and the endpoint's response, Reference
{{authority-commitment}}. It defines no registry of `typ` values.

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
