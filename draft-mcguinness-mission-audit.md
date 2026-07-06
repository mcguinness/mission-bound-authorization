---
title: "Mission Audit Transparency"
abbrev: "Mission Audit Transparency"
category: std

docname: draft-mcguinness-mission-audit-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - oauth
 - mission
 - agent
 - audit
 - transparency
 - scitt
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-audit.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC3339:
  RFC6234:
  RFC8785:
  RFC9052:
  RFC9943:
  I-D.draft-ietf-cose-hash-envelope:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

informative:
  I-D.draft-ietf-scitt-scrapi:
  I-D.draft-mcguinness-oauth-mission-consent-evidence:
    title: "Mission Consent Evidence for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-consent-evidence.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-authzen:
    title: "Mission-Bound Runtime Enforcement: AuthZEN Profile"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-authzen.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-signals:
    title: "Mission Lifecycle Signals for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-signals.html
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
  I-D.draft-mcguinness-oauth-mission-child-delegation:
    title: "Mission Child Delegation for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-child-delegation.html
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
  I-D.draft-mcguinness-mission-authority-server:
    title: "Mission Authority Server"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-authority-server.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

--- abstract

Mission-Bound Authorization for OAuth 2.0 and its companions produce
many evidence records: the approval event, lifecycle transitions,
consent evidence, runtime decision and execution evidence, and further
evidence types profiles define. Each is signed, but signed
is not the same as tamper-evident, append-only, or independently
verifiable: a holder of the signing key can still backdate, drop, or
reorder records, and a cross-domain party cannot confirm what was
recorded without trusting the issuer's own logs. This document defines
an OPTIONAL Mission Audit Transparency profile. It registers Mission
evidence into a SCITT Transparency Service as Signed Statements, with
the Mission as the statement subject so a Mission's records form one
coherent, append-only feed, and binds the resulting Receipt back so any
party, in any domain, can verify offline that a record was registered
and not altered. To keep sensitive task data out of the log, statements
commit to the evidence by hash rather than carrying it.

--- middle

# Introduction

Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} (the "issuance profile") and
its companions record evidence at every
governance and enforcement point. The evidence is signed, which makes a
single record attributable and tamper-evident in isolation. It does not
make the record set as a whole trustworthy: the party that holds the
signing key can backdate a record, omit an inconvenient one, or present
different histories to different auditors, and nothing a relying party
holds detects it. A cross-domain auditor is worse off still, with only
the issuer's assertion that its logs are complete.

This document closes that gap by profiling the SCITT architecture
{{RFC9943}} (the "transparency substrate"). A
Mission evidence record is registered with a Transparency Service as a
Signed Statement; the service appends it to a verifiable, non-equivocating
log and returns a Receipt proving inclusion. The Signed Statement plus
its Receipt is a Transparent Statement that any party can verify offline:
the record was registered, at a committed time, in a log that cannot
later drop or reorder it. The Mission is the statement subject, so all of
a Mission's evidence shares one subject and forms one feed an auditor can
assemble and replay as a single narrative ({{retrieval}}).

This adds transparency to evidence the suite already defines; it defines
no new evidence object. It is OPTIONAL, and what it proves is bounded:
transparency makes misbehavior detectable and attributable, it does not
make a dishonest issuer honest ({{limits}}).

# Status: An OPTIONAL Extension {#optional-status}

This document is OPTIONAL. A deployment that retains evidence without a
Transparency Service is fully conformant to the issuance profile and its
companions and is unaffected by this document. It places no new
requirement on them and defines no new evidence; it registers the
records they already produce.

A deployment claims this profile only when it registers Mission evidence
with a Transparency Service.

The transparency substrate this profile builds on is ratified: it
depends normatively on the SCITT architecture {{RFC9943}}, a published
standard. Its hash commitment uses the COSE hash-envelope headers
({{I-D.draft-ietf-cose-hash-envelope}}), approved and in the RFC
Editor queue. The profile itself is newer than the substrate and less
exercised in deployment, so an implementer treats its interfaces as
still settling and validates them against real audits before relying on
them. The signed evidence the suite produces without a Transparency
Service ({{I-D.draft-mcguinness-oauth-mission}}) does not depend on this
profile.

# Relationship to the Issuance Profile {#issuance-relationship}

This document depends normatively on the issuance profile and the
transparency substrate, and is not implementable alone. It reuses the
issuance profile's `mission` claim and integrity anchors, the evidence
objects defined across the suite, and the transparency substrate's
Signed Statement, Receipt, Transparent Statement, and subject (feed)
constructs and COSE_Sign1 {{RFC9052}} format. It uses Mission, Mission
Issuer, and the evidence objects as the suite defines them, and
Transparency Service, Signed Statement, Receipt, and Transparent
Statement as the transparency substrate defines them.

# Conventions and Terminology {#conventions}

{::boilerplate bcp14-tagged}

Mission evidence:
: Any evidence record the suite defines, including the approval event,
  lifecycle transitions, consent evidence
  ({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}), and runtime
  decision and execution evidence
  ({{I-D.draft-mcguinness-mission-runtime}}).

# Mission Substrate {#mission-substrate}

This profile is defined against the Mission model rather than against
OAuth 2.0 mechanics. It consumes these substrate primitives: the
Mission identifier and issuer, from which the statement subject is
constructed; the evidence types and their canonical bytes; the
integrity-anchor envelope; and each producer's published key material.
The issuance profile {{I-D.draft-mcguinness-oauth-mission}} is this
version's normative substrate. Evidence produced under another Mission
substrate registers and verifies the same way once its types and
canonical bytes are defined as in the evidence-type table
({{evidence-types}}).

# Registering Mission Evidence {#registration}

A producer of Mission evidence (the Mission Issuer, a Policy Decision
Point, a harness, or another component the deployment trusts to record)
MAY register a record with a Transparency Service as a Signed Statement
({{RFC9943}}). The Signed Statement's protected header carries, in its
CWT Claims:

- `iss`: the producing component's issuer identifier, bound to the key
  the record is signed with; and
- `sub`: the Mission, as defined in {{feed}}.

## Hash Commitment {#hash-commitment}

A Signed Statement MUST commit to the evidence by hash rather than carry
the evidence itself, so sensitive task data stays out of the log
({{privacy-considerations}}). The commitment uses the COSE hash-envelope
mechanism {{I-D.draft-ietf-cose-hash-envelope}}: the COSE_Sign1 payload
is the hash of the evidence, carried inline, and the protected header
signals how the hash was produced. The payload is not detached, and it
is not the `sha-256:...` display string an integrity anchor uses
({{I-D.draft-mcguinness-oauth-mission}}); it is the digest bytes
themselves.

The committed value is the SHA-256 {{RFC6234}} digest of the evidence
bytes that {{evidence-types}} fixes for the evidence type. For an object
that is already signed, those bytes are the retained object as issued,
hashed as-is; for an object this profile canonicalizes, they are its JCS
canonical bytes. The protected header carries:

- `payload-hash-alg` (label 258): the COSE algorithm of the hash, `-16`
  for SHA-256 {{I-D.draft-ietf-cose-hash-envelope}}; and
- `preimage-content-type` (label 259): the media type of the evidence
  that was hashed, from {{evidence-types}}.

The log then proves a specific record was registered at a time; the
evidence is retrieved separately, under access control, and its
canonical bytes are rehashed and checked against the committed digest
({{receipts}}).

## Evidence Types {#evidence-types}

Each registrable evidence type fixes the exact bytes that are hashed,
the media type carried in `preimage-content-type`, and the producer
authoritative for it. A producer MUST commit to the canonical bytes
named here, and a relying party MUST verify the producer is
authoritative for the type ({{registration-policy}}) before treating a
record as part of the Mission's feed.

| Evidence type | Canonical bytes (hashed) | `preimage-content-type` | Producer |
|---|---|---|---|
| Approval event | Mission record at creation, `state` excluded, canonicalized | `application/mission-approval-record+json` | `issuer` |
| Lifecycle transition | Signals SET as issued; else {{transition-object}} (JCS) | `application/secevent+jwt`, else `application/mission-lifecycle-transition+json` | `issuer` |
| Derivation record | {{derivation-record}} (JCS) | `application/mission-derivation-record+json` | `issuer` |
| Consent evidence | retained signed object, as issued | `application/mission-consent-evidence+json` | `issuer` |
| Decision evidence | Decision Evidence object, as issued | `application/mission-decision-evidence+json` | PDP key |
| Execution evidence | Execution Evidence object, as issued | `application/mission-execution-evidence+json` | PEP key |
| Mission Mandate | JWS Compact Serialization, as issued | `application/mission-mandate+jwt` | `issuer` |

The table is extensible by specification: a profile MAY define an
additional evidence type by fixing its canonical bytes, its
`preimage-content-type`, and its authoritative producer, as the
Mandate profile does for the Mission Mandate
({{I-D.draft-mcguinness-mission-mandate}}). A relying party admits an
extension type it implements; it ignores records of a type it does
not implement, and they are not audit failures.

The producer identifiers are principals the suite already names. For
every record whose producer is the Mission `issuer`, the Signed
Statement's `iss` MUST equal that `issuer`
({{I-D.draft-mcguinness-oauth-mission}}). The PDP and PEP keys are those
in the deployment-published key sets the runtime and AuthZEN profiles
require ({{I-D.draft-mcguinness-mission-runtime}},
{{I-D.draft-mcguinness-mission-authzen}}).

The approval event, the lifecycle-transition object, and the
derivation record are canonicalized
under the issuance profile's canonicalization rules
({{I-D.draft-mcguinness-oauth-mission}}); an already-signed object (the
consent, decision, and execution evidence, the Signals SET, and the
Mandate) is
hashed as issued, not re-canonicalized. The approval-event,
lifecycle-transition, and derivation-record media types are defined by
this profile ({{iana}});
the consent, decision, and execution evidence types are registered by
the profiles that define those objects
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}},
{{I-D.draft-mcguinness-mission-authzen}}), the Signals SET
media type by the Signals profile it is carried in
({{I-D.draft-mcguinness-oauth-mission-signals}}), and the Mandate
media type by the Mandate profile
({{I-D.draft-mcguinness-mission-mandate}}).

### The Lifecycle Transition Object {#transition-object}

A deployment that does not run the Signals profile commits a lifecycle
transition as a minimal JSON object with these members, JCS-canonicalized
{{RFC8785}}:

- `mission_id` (string, required): the Mission `id`.
- `issuer` (string, required): the Mission `issuer`.
- `state` (string, required): the new lifecycle state.
- `prior_state` (string, optional): the state immediately before the
  transition.
- `transitioned_at` (string, required): an RFC 3339 {{RFC3339}}
  date-time at which the transition was committed.

Its media type is `application/mission-lifecycle-transition+json`
({{iana}}).

#### Computed Example {#transition-vector}

A minimal transition object recording the revocation of Mission
`msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-`:

~~~ json
{
  "mission_id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
  "issuer": "https://as.example.com",
  "state": "revoked",
  "transitioned_at": "2026-11-02T08:30:00Z"
}
~~~

Its JCS canonical bytes (one line; breaks are for display only):

~~~ text
{"issuer":"https://as.example.com","mission_id":"msn_8RfX2Lqv9TqMv
4z7sA2bN1k0YpEdHc9-","state":"revoked","transitioned_at":"2026-11-
02T08:30:00Z"}
~~~

The committed digest is the SHA-256 of those bytes; its base64url
form is `9xMd0Ge2W5oh7f_a964mvK66QOOHYOe-kDz3HUYXkd8`. The Signed
Statement carries the digest bytes inline as its payload, with this
protected header ({{hash-commitment}}, {{feed}}):

~~~ cbor-diag
{
  / alg /                    1: -7,   / ES256 /
  / payload-hash-alg /     258: -16,  / SHA-256 /
  / preimage-content-type / 259: "application/mission-lifecycle-transition+json",
  / kid /                    4: h'61732d6b65792d323032362d7133',
  / CWT Claims /            15: {
    / iss / 1: "https://as.example.com",
    / sub / 2: "https://as.example.com/missions/msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-"
  }
}
~~~

### The Derivation Record {#derivation-record}

The family's evidence runs from the approval to the enforced action,
but the derivation event between them, the `issuer` issuing a token
under the Mission ({{I-D.draft-mcguinness-oauth-mission}}), is
otherwise visible only in Authorization Server logs no profile
mandates. A derivation record closes that gap: it commits which token
was issued, to which audience, carrying which entries, under which
Mission.

A derivation record is a JSON object with these members,
JCS-canonicalized {{RFC8785}}:

- `mission_id` (string, required): the Mission `id`.
- `issuer` (string, required): the Mission `issuer`.
- `token_digest` (string, required): a digest in the issuance
  profile's encoded form ({{I-D.draft-mcguinness-oauth-mission}}),
  over the UTF-8 bytes of the issued token's JWS Compact
  Serialization, or of the token's `jti` where the deployment retains
  no token bytes.
- `aud` (string, required): the audience the token was issued for.
- `entries_digest` (string, required): the integrity-anchor envelope
  digest ({{I-D.draft-mcguinness-oauth-mission}}) over the issued
  `authorization_details` array, with `typ`
  `mission-derivation-entries` and `iss` the `issuer`.
- `actor` (string, optional): the delegate's `sub`, present when the
  derivation was a delegation.
- `issued_at` (string, required): an RFC 3339 {{RFC3339}} date-time at
  which the token was issued.

Its media type is `application/mission-derivation-record+json`
({{iana}}), and its authoritative producer is the `issuer`: the Signed
Statement's `iss` MUST equal the Mission `issuer`
({{evidence-types}}).

#### Computed Example {#derivation-vector}

For Mission `msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-`, the Mission Issuer issues
a token for audience `https://erp.example.com`, narrowed to the write
entry, with `jti` `at_5v9Kq2mR7xW4nP8sL1zT6`. The issued
`authorization_details`:

~~~ json
[
  { "type": "mission_resource_access",
    "resource": "https://erp.example.com",
    "actions": ["journal-entries.write"],
    "constraints":
      { "max_amount": { "amount": "500.00", "currency": "USD" } } }
]
~~~

`entries_digest` is the integrity-anchor envelope digest over that
array with `typ` `mission-derivation-entries` and `iss`
`https://as.example.com`; `token_digest` is over the UTF-8 bytes of
the `jti`. The derivation was not a delegation, so `actor` is absent.
The record:

~~~ json
{
  "mission_id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
  "issuer": "https://as.example.com",
  "token_digest":
    "sha-256:V1Wbh4Z3wK39B_YmzHlvkGr7hEA1rUoJMuj00y0q-eE",
  "aud": "https://erp.example.com",
  "entries_digest":
    "sha-256:Hilv4npLEWlcp2y5z7xcACgXxRhx-LO6dqs5AX0xL8o",
  "issued_at": "2026-10-15T14:32:12Z"
}
~~~

Its JCS canonical bytes (one line; breaks are for display only):

~~~ text
{"aud":"https://erp.example.com","entries_digest":"sha-256:Hilv4np
LEWlcp2y5z7xcACgXxRhx-LO6dqs5AX0xL8o","issued_at":"2026-10-15T14:3
2:12Z","issuer":"https://as.example.com","mission_id":"msn_8RfX2Lq
v9TqMv4z7sA2bN1k0YpEdHc9-","token_digest":"sha-256:V1Wbh4Z3wK39B_Y
mzHlvkGr7hEA1rUoJMuj00y0q-eE"}
~~~

The committed digest is the SHA-256 of those bytes; its base64url
form is `_cM7GYYiV3VI-QrtRWSogl5Wz1-sB90GM4ZHxuPC3j0`. The Signed
Statement carries the digest bytes inline as its payload, with
`preimage-content-type` `application/mission-derivation-record+json`
and the same `iss` and `sub` as {{transition-vector}}.

## Registration Policy and Authoritative Producers {#registration-policy}

Each evidence type has one authoritative producer ({{evidence-types}}).
A relying party MUST verify that a record's `iss` is the authoritative
producer for the record's type before treating the record as part of the
Mission's feed; a record from any other producer is not part of the
feed, whatever its `sub`.

The deployment's Transparency Service registration policy SHOULD restrict
who may register Signed Statements for a Mission subject to those
authoritative producers, so the log does not accumulate records from
components that are not entitled to write to a Mission's feed.

A relying party discovers a producer's key by the producer's role. The
`issuer`'s key is resolved through its published key material: the
Authorization Server's metadata `jwks_uri` in the OAuth binding
({{I-D.draft-mcguinness-oauth-mission}}), or the Mission Authority
Server's discovery `jwks_uri` in the standalone binding
({{I-D.draft-mcguinness-mission-authority-server}}). A PDP or PEP key
is resolved
through the deployment-published key sets the runtime and AuthZEN
profiles require ({{I-D.draft-mcguinness-mission-runtime}},
{{I-D.draft-mcguinness-mission-authzen}}).

## Registration Availability {#availability}

Registration is asynchronous to the events it records. A producer MUST
NOT block approval, issuance, or a lifecycle transition on a Transparency
Service being reachable or on a Receipt being returned; the governed
operation proceeds and the record is registered out of band. A conforming
deployment registers each record within a documented time bound and
records its registration backlog, so a gap between an event and its
registration is visible rather than silent.

A record registered late is transparent only from its registration time:
the Receipt proves inclusion from when the log received the Signed
Statement, not from when the event occurred. A deployment that needs the
event time itself attested relies on the timestamps the evidence carries,
which the record's hash commits.

## Retrieval {#retrieval}

The transparency substrate registers Signed Statements and resolves a
Receipt by its entry identifier; the SCITT reference APIs
{{I-D.draft-ietf-scitt-scrapi}} give a concrete interface for
registration, Receipt resolution, and Transparency Service key discovery
where a deployment runs them. Neither the substrate nor those APIs
defines a query that enumerates a subject's whole feed. A deployment that
wants an auditor to retrieve all of a Mission's records by `sub` provides
that enumeration itself, out of band, over the records it registered;
this profile fixes the `sub` so those records share one correlator
({{feed}}), not a standardized feed query.

## What to Register {#what-to-register}

A deployment claiming this profile MUST register at least the
governance-critical records: the approval event and every Mission
lifecycle transition. It SHOULD also register the runtime decision and
execution evidence for the action classes it enforces, so the action
trail is transparent and not only the governance trail.

A Mission Issuer deploying this profile SHOULD register a derivation record
({{derivation-record}}) for each derivation event. The derivation is
where approval becomes an issued token, and the family's evidence
otherwise leaves that step to Authorization Server logs no profile
mandates; registering it closes the approval-to-action gap.

# The Mission as Subject {#feed}

The `sub` of every Signed Statement about a Mission is a stable
identifier of that Mission, derived from the `mission` claim's `issuer`
and `id`. All evidence about one Mission shares one `sub` and forms one
Transparency Service feed. Where the deployment provides feed retrieval
({{retrieval}}), an auditor collects a Mission's complete, ordered,
append-only evidence by that `sub`, and the substrate's non-equivocation
guarantee means the auditor and the deployment see the same records.

For that to hold, every producer MUST compute the identical `sub`. This
profile fixes a single construction; a producer MUST use it and MUST NOT
use any other. The `sub` is the URI formed by appending the literal path
segment `missions` and the Mission `id` to the `issuer`:

~~~ text
<issuer>/missions/<id>
~~~

The `issuer` is used exactly as it appears in the `mission` claim, with
any single trailing slash removed, and the `id` is appended without
transformation; the issuance profile constrains the Mission Identifier
to the URL-safe characters `[A-Za-z0-9_-]` ({{I-D.draft-mcguinness-oauth-mission}}),
so no percent-encoding is required. Because the construction is fixed,
independent producers writing evidence about the same Mission (the
Mission Issuer, a PDP, a harness) compute the same `sub` and write to one
feed.

The `sub` is a correlator, not a credential; presenting it authorizes
nothing ({{I-D.draft-mcguinness-oauth-mission}}).

A Child Mission ({{I-D.draft-mcguinness-oauth-mission-child-delegation}})
is its own Mission with its own `id` and `issuer`, so its evidence forms
its own feed; its lifecycle events, including a `cascaded` transition,
appear in that feed. The event that triggered the cascade is in the
parent's feed, and the child's lineage to the parent is the `parent`
member of its `mission` claim, which an auditor follows to the parent's
`sub` to see that trigger.

Across trust domains a Mission's `issuer` and `id` are unchanged
({{I-D.draft-mcguinness-oauth-mission}}), so every producer in every
domain computes the same `sub`. They share one feed only when they
register with the same Transparency Service. Where domains register with
different services, each service holds a partial feed and its
non-equivocation guarantee is per-service ({{receipts}}); an auditor
that needs the Mission's whole history reconciles it across those
services, and a deployment that wants a single coherent feed SHOULD have
its cross-domain producers register with one shared service.

# Receipts and Transparent Statements {#receipts}

On registration the Transparency Service returns a Receipt, a signed
inclusion proof ({{RFC9943}}). The producer
SHOULD retain the Receipt with the evidence, or on the Mission record,
as a Transparent Statement (the Signed Statement augmented with its
Receipt).

A relying party verifies a Transparent Statement offline, without
contacting the producer or the service:

1. verify the Signed Statement signature against the producing
   component's (`iss`) trust anchor;
2. verify the Receipt signature against the Transparency Service's
   published key or configured trust anchor;
3. verify the inclusion proof binds the Signed Statement to the log;
4. when auditing a specific Mission, confirm `sub` is that Mission's
   feed ({{feed}}); and
5. retrieve the referenced evidence under access control, rehash the
   evidence bytes as {{evidence-types}} fixes them for its type (with the
   retained salt, where one was used, {{privacy-considerations}}), and
   compare the result against the committed digest.

A relying party MUST complete steps 1 through 5 before relying on a
record as transparent.

## Verification Failures {#verification-failures}

This profile distinguishes an integrity failure, where the transparency
claim is false, from an audit failure, where the claim cannot be fully
checked but is not refuted, as the consent evidence profile does
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}):

- A failed Signed Statement signature, Receipt signature, or inclusion
  proof (steps 1 through 3), or a committed hash that does not match the
  retrieved evidence (step 5), is an integrity failure. The relying
  party MUST reject the Transparent Statement and MUST NOT treat the
  record as transparent.
- Evidence that cannot be retrieved within the retention window (step 5
  incomplete) is an audit failure, not an integrity failure. Steps 1
  through 3 still establish that the record was registered, at a
  committed time, in a non-equivocating log; only the content check is
  incomplete. The relying party MUST NOT treat the record as
  content-verified, and MUST NOT treat unretrievable evidence as
  evidence of tampering.
- A producer or Transparency Service key that the relying party cannot
  verify against a trust anchor (step 1 or step 2 unresolved) is an audit
  failure, not an integrity failure. The relying party cannot attribute
  the Signed Statement or the Receipt to a known key, so it MUST NOT
  treat the record as transparent; it is not evidence of tampering, and
  the relying party MUST NOT treat it as such.

A deployment MAY register the same evidence with more than one
Transparency Service and retain multiple Receipts. A relying party
detects equivocation by comparing two things across services: the
Receipts issued for the same Signed Statement, which must prove inclusion
of the identical statement, and the records listed for the same `sub`,
which must not differ in ways the append-only property forbids. A service
that presents inconsistent Receipts for one statement, or a subject
listing that diverges from another service's, is equivocating, and the
relying party can rely on the others.

# Worked Example {#example}

At the approval event for Mission
`msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-`, the Mission Issuer records
Consent Evidence and registers it. It does not put the disclosure in the
log; it signs a Signed Statement whose payload is the hash of the Consent
Evidence, carried inline, with the hash algorithm and the evidence media
type in the protected header ({{hash-commitment}}). The `sub` is the
Mission feed, derived from the Mission `issuer` and `id`; the `iss` is
the Mission Issuer. Protected header, in COSE EDN ({{RFC9052}}):

~~~ cbor-diag
{
  / alg /                    1: -7,   / ES256 /
  / payload-hash-alg /     258: -16,  / SHA-256 /
  / preimage-content-type / 259: "application/mission-consent-evidence+json",
  / kid /                    4: h'61732d6b65792d323032362d7133',
  / CWT Claims /            15: {
    / iss / 1: "https://as.example.com",
    / sub / 2: "https://as.example.com/missions/msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-"
  }
}
~~~

The payload is the SHA-256 digest of the retained Consent Evidence object
as issued ({{evidence-types}}), carried inline as the raw digest whose
base64url form is `CnS3nT9sQ7nM2vL4tY6bD1eF8jC5wH0pV2nR3kQ4xVz`, not that
display string. The Transparency Service appends the statement
and returns a Receipt, a COSE_Sign1 with an inclusion proof in its
unprotected header, which the Mission Issuer keeps with the evidence as a
Transparent Statement.

As the Mission proceeds, its other producers write to the same `sub`:
the Mission Issuer registers a derivation record when it derives the
agent's token ({{derivation-record}}), the
PDP registers a decision-evidence commitment when it permits the
`journal-entries.write`, and the Mission Issuer registers a
lifecycle-change commitment when `alice` later completes the Mission.
Collecting the records registered under that one `sub` ({{retrieval}})
gives the Mission's whole history, in order, append-only:

~~~ text
sub = https://as.example.com/missions/msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-

  #1  approval-event        iss=as.example.com    t0
  #2  consent-evidence      iss=as.example.com    t0
  #3  derivation-record     iss=as.example.com    t0
  #4  decision-evidence     iss=pdp.example.com   t0+6h
  #5  lifecycle: completed  iss=as.example.com    t0+6h
~~~

A compliance auditor in another domain, holding none of these
deployments' logs, takes the Transparent Statement for #2, verifies the
Receipt against the Transparency Service's published key and the
inclusion proof, retrieves the Consent Evidence under access control,
and rehashes the retained object to compare against the committed digest.
The auditor now knows that exact disclosure was registered at `t0` and
has not since been altered, dropped, or reordered, without trusting the
Mission Issuer's own records.

Two failures are distinct ({{verification-failures}}). If the retrieved
Consent Evidence hashes to a value other than the committed digest, the
retained record was altered after registration: an integrity failure,
and the auditor rejects it. If the
record cannot be retrieved at all, the auditor still knows from the
Receipt that record #2 was registered at `t0` and not reordered, but
cannot confirm its content: an audit failure, not proof of tampering.

# What Transparency Adds, and Does Not {#limits}

Transparency makes the evidence set tamper-evident and independently
verifiable: a registered record cannot be silently backdated, dropped,
or reordered, the feed is the same for every auditor, and a cross-domain
party verifies a record without trusting the producer's logs, which a
bare signature over a narrowed token cannot give it
({{I-D.draft-mcguinness-oauth-mission}}).

It does not make a dishonest producer honest. A producer can register a
false record; transparency makes the false record permanent, attributable,
and visible to every auditor, which is accountability, not prevention,
the transparency substrate's own model
({{RFC9943}}). It also proves only that a
record was registered, not that the action the record describes occurred
or was authorized; that is the evidence's own semantics. And because
statements commit by hash, a Receipt without the retrievable evidence
proves only that some record was logged, not what it said.

# Conformance {#conformance}

A producer conforming to this profile MUST:

- register Mission evidence as Signed Statements that commit to the
  evidence by an inline hash, never the evidence in the clear
  ({{registration}});
- set `sub` to the Mission feed by the fixed construction of {{feed}};
- set `iss` to its own issuer identifier, bound to the signing key; and
- register at least the approval event and every Mission lifecycle
  transition ({{registration}}).

A relying party conforming to this profile MUST:

- perform verification steps 1 through 5 of {{receipts}} before relying
  on a record as transparent;
- treat a signature, Receipt, inclusion-proof, or committed-hash
  mismatch as an integrity failure and reject the record;
- treat unretrievable evidence as an audit failure, not as evidence of
  tampering ({{verification-failures}}); and
- treat a producer or Transparency Service key it cannot verify against a
  trust anchor as an audit failure, and not treat the record as
  transparent ({{verification-failures}}).

# Security Considerations {#security-considerations}

The transparency substrate's security considerations apply. This
profile adds:

- Accountability, not prevention. Transparency detects and attributes
  tampering and omission after the fact; it does not stop a producer
  from registering a false record ({{limits}}).
- Transparency Service trust. A single service is trusted not to
  equivocate; a deployment that needs that property checked SHOULD
  register with multiple independent services ({{receipts}}).
- Completeness. Transparency proves what was registered, not that
  everything was registered. A producer that omits a record cannot
  forge inclusion, but the gap is visible only if an auditor expects the
  record; a deployment SHOULD register evidence on a predictable schedule
  so omissions stand out in the feed.
- Receipt and key management. A Receipt is only as trustworthy as the
  Transparency Service key that signs it; relying parties manage those
  trust anchors as they do the producers'.
- Log lifecycle. Transparency Service key rotation, log retirement, and
  migration of a Mission's feed between services are deferred to future
  work, and a deployment whose Missions outlive a single log instance
  handles them by local arrangement until then.

# Privacy Considerations {#privacy-considerations}

A Transparency Service log is append-only and may be widely readable, so
nothing registered can be redacted later. A producer MUST NOT register
Mission evidence in the clear; it registers an inline hash commitment
({{registration}}), and the evidence, which can carry task descriptions,
principals, and high-risk authority, is retained separately under access
control. Even the committed metadata leaks
information: the `sub` is a durable per-Mission correlator and the
registration times reveal a Mission's activity pattern. The `sub`
construction is fixed ({{feed}}) and does not expose the Subject
directly, so the concern is not Subject leakage but that the Mission's
durable identifier, its existence, and its registration cadence are
visible in the log. A deployment SHOULD weigh whether those are
sensitive, and whether the `issuer` and `id` that compose the `sub`
reveal more than intended, before registering a Mission's evidence in a
shared or widely readable log.

Evidence whose canonical bytes are low-entropy or drawn from an
enumerable space MUST be committed with a random salt, retained
alongside the evidence and hashed together with the evidence's canonical
bytes. Without a salt, a party that can guess the evidence can confirm
the commitment by dictionary; the salt makes the committed digest
unguessable while still reproducible at verification, where the salt is
retrieved with the evidence ({{receipts}}).

Deleting retained evidence has a consequence the log makes permanent. The
Receipt, the `sub`, and the registration cadence stay in the log, but the
evidence they commit to is gone, so every record over the erased evidence
becomes a permanent audit failure ({{verification-failures}}): its
content can never again be checked against the commitment. A deployment
that may need to erase evidence, for a data-subject request or a
retention limit, weighs this before registering. Registration does not
prevent erasure; it converts an erased record into a permanent, visible
gap rather than a silent one.

# IANA Considerations {#iana}

This document defines three media types for the evidence types of
{{evidence-types}} that no other profile defines:
`application/mission-approval-record+json` for the approval-event record,
`application/mission-lifecycle-transition+json` for the minimal
lifecycle-transition object ({{transition-object}}), and
`application/mission-derivation-record+json` for the derivation record
({{derivation-record}}). This document makes
no registration request for them yet; registration is deferred pending a
demonstrated cross-domain interoperability need, and deployments using
these media types do so by local agreement until then.

The other evidence media types this profile registers into a Transparency
Service are defined elsewhere: the runtime decision and execution
evidence types by the AuthZEN profile
({{I-D.draft-mcguinness-mission-authzen}}), the consent evidence
type by the consent evidence profile
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}), the
Mission Mandate media type by the Mandate profile
({{I-D.draft-mcguinness-mission-mandate}}), and the
Signals SET media type `application/secevent+jwt` by RFC 8417, which the
Signals profile carries the event in
({{I-D.draft-mcguinness-oauth-mission-signals}}). The Signed Statement
and Receipt media types are the transparency substrate's ({{RFC9943}}).
This profile derives the `sub` by profile rather than registering a new
identifier.

--- back

# Acknowledgments
{:numbered="false"}

This document is part of the Mission-Bound Authorization for OAuth 2.0
work and profiles the SCITT architecture to make Mission evidence
transparent and independently verifiable.
