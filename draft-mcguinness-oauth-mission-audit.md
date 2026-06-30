---
title: "Mission Audit Transparency for OAuth 2.0"
abbrev: "OAuth Mission Audit Transparency"
category: std

docname: draft-mcguinness-oauth-mission-audit-latest
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
  github: "mcguinness/draft-mcguinness-oauth-mission"
  latest: "https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-oauth-mission-audit.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC9052:
  I-D.draft-ietf-scitt-architecture:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-latest

informative:
  I-D.draft-mcguinness-oauth-mission-consent-evidence:
    title: "Mission Consent Evidence for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-consent-evidence-latest
  I-D.draft-mcguinness-oauth-mission-runtime:
    title: "Mission-Bound Runtime Enforcement for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-runtime-latest
  I-D.draft-mcguinness-oauth-mission-child-delegation:
    title: "Child Mission Delegation for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-child-delegation-latest

--- abstract

Mission-Bound Authorization for OAuth 2.0 and its companions produce
many evidence records: the approval event, lifecycle transitions,
consent evidence, runtime decision and execution evidence, and harness,
orchestration, and child-delegation evidence. Each is signed, but signed
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

The issuance profile {{I-D.draft-mcguinness-oauth-mission}} (the
"issuance profile") and its companions record evidence at every
governance and enforcement point. The evidence is signed, which makes a
single record attributable and tamper-evident in isolation. It does not
make the record set as a whole trustworthy: the party that holds the
signing key can backdate a record, omit an inconvenient one, or present
different histories to different auditors, and nothing a relying party
holds detects it. A cross-domain auditor is worse off still, with only
the issuer's assertion that its logs are complete.

This document closes that gap by profiling the SCITT architecture
{{I-D.draft-ietf-scitt-architecture}} (the "transparency substrate"). A
Mission evidence record is registered with a Transparency Service as a
Signed Statement; the service appends it to a verifiable, non-equivocating
log and returns a Receipt proving inclusion. The Signed Statement plus
its Receipt is a Transparent Statement that any party can verify offline:
the record was registered, at a committed time, in a log that cannot
later drop or reorder it. The Mission is the statement subject, so all of
a Mission's evidence is one feed an auditor retrieves and replays as a
single narrative.

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
  ({{I-D.draft-mcguinness-oauth-mission-runtime}}).

# Registering Mission Evidence {#registration}

A producer of Mission evidence (the Mission Issuer, a Policy Decision
Point, a harness, or another component the deployment trusts to record)
MAY register a record with a Transparency Service as a Signed Statement
({{I-D.draft-ietf-scitt-architecture}}). The Signed Statement's
protected header carries, in its CWT Claims:

- `iss`: the producing component's issuer identifier, bound to the key
  the record is signed with; and
- `sub`: the Mission, as defined in {{feed}}.

The `content_type` identifies the evidence object's media type.

A Signed Statement MUST commit to the evidence by hash, with a detached
payload, rather than carry the evidence itself
({{I-D.draft-ietf-scitt-architecture}}). The committed value is the
evidence's existing integrity anchor or evidence-envelope digest
({{I-D.draft-mcguinness-oauth-mission}}); where the evidence has no such
anchor, the producer computes one over the evidence's canonical bytes.
This keeps sensitive task data out of the log
({{privacy-considerations}}): the log proves a specific record was
registered at a time, and the record is retrieved separately, under
access control, and checked against the committed hash.

A deployment claiming this profile MUST register at least the
governance-critical records: the approval event and every Mission
lifecycle transition. It SHOULD also register the runtime decision and
execution evidence for the action classes it enforces, so the action
trail is transparent and not only the governance trail.

# The Mission as Subject {#feed}

The `sub` of every Signed Statement about a Mission is a stable
identifier of that Mission, derived from the `mission` claim's `origin`
and `id`. All evidence about one Mission shares one `sub` and forms one
Transparency Service feed. An auditor retrieves a Mission's complete,
ordered, append-only evidence by that `sub`, and the substrate's
non-equivocation guarantee means the auditor and the deployment see the
same feed.

For that to hold, every producer MUST compute the identical `sub`. This
profile fixes a single construction; a producer MUST use it and MUST NOT
use any other. The `sub` is the URI formed by appending the literal path
segment `missions` and the Mission `id` to the `origin`:

~~~ text
<origin>/missions/<id>
~~~

The `origin` is used exactly as it appears in the `mission` claim, with
any single trailing slash removed, and the `id` is appended without
transformation; the issuance profile constrains `mission_id` to the
URL-safe characters `[A-Za-z0-9_-]` ({{I-D.draft-mcguinness-oauth-mission}}),
so no percent-encoding is required. Because the construction is fixed,
independent producers writing evidence about the same Mission (the
Mission Issuer, a PDP, a harness) compute the same `sub` and write to one
feed.

The `sub` is a correlator, not a credential; presenting it authorizes
nothing ({{I-D.draft-mcguinness-oauth-mission}}).

A Child Mission ({{I-D.draft-mcguinness-oauth-mission-child-delegation}})
is its own Mission with its own `id` and `origin`, so its evidence forms
its own feed; its lifecycle events, including a `cascaded` transition,
appear in that feed. The event that triggered the cascade is in the
parent's feed, and the child's lineage to the parent is the `parent`
member of its `mission` claim, which an auditor follows to the parent's
`sub` to see that trigger.

Across trust domains a Mission's `origin` and `id` are unchanged
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
inclusion proof ({{I-D.draft-ietf-scitt-architecture}}). The producer
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
5. retrieve the referenced evidence under access control and verify it
   against the committed detached hash.

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
- Evidence that cannot be retrieved within the access window (step 5
  incomplete) is an audit failure, not an integrity failure. Steps 1
  through 3 still establish that the record was registered, at a
  committed time, in a non-equivocating log; only the content check is
  incomplete. The relying party MUST NOT treat the record as
  content-verified, and MUST NOT treat unretrievable evidence as
  evidence of tampering.
- A producer or Transparency Service key that is not among the relying
  party's trust anchors leaves the corresponding step unverified rather
  than failed: the statement then asserts no more than the relying party
  can check.

A deployment MAY register the same evidence with more than one
Transparency Service and retain multiple Receipts; a relying party that
distrusts one service can then rely on another, and equivocation by one
service is detectable against the others.

# Worked Example {#example}

At the approval event for Mission
`msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-`, the Mission Issuer records
Consent Evidence and registers it. It does not put the disclosure in the
log; it signs a Signed Statement whose payload is detached and whose
`content_type` names the evidence, committing to the evidence by its
`consent_rendering_hash`. The `sub` is the Mission feed, derived from the
Mission `origin` and `id`; the `iss` is the Mission Issuer. Protected
header, in COSE EDN ({{RFC9052}}):

~~~ cbor-diag
{
  / alg /          1: -7,             / ES256 /
  / content_type / 3: "application/mission-consent-evidence+json",
  / kid /          4: h'61732d6b65792d323032362d7133',
  / CWT Claims /  15: {
    / iss / 1: "https://as.example.com",
    / sub / 2: "https://as.example.com/missions/msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-"
  }
}
~~~

The signed payload is detached; the committed value is the evidence's
`consent_rendering_hash`,
`sha-256:CnS3nT9sQ7nM2vL4tY6bD1eF8jC5wH0pV2nR3kQ4xVz`. The Transparency
Service appends the statement and returns a Receipt, a COSE_Sign1 with an
inclusion proof in its unprotected header, which the Mission Issuer keeps
with the evidence as a Transparent Statement.

As the Mission proceeds, its other producers write to the same `sub`: the
PDP registers a decision-evidence commitment when it permits the
`journal-entries.write`, and the Mission Issuer registers a
lifecycle-change commitment when `alice` later completes the Mission.
Querying the Transparency Service for that one `sub` returns the Mission's
whole history, in order, append-only:

~~~ text
sub = https://as.example.com/missions/msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-

  #1  approval-event        iss=as.example.com    t0
  #2  consent-evidence      iss=as.example.com    t0
  #3  decision-evidence     iss=pdp.example.com   t0+6h
  #4  lifecycle: completed  iss=as.example.com    t0+6h
~~~

A compliance auditor in another domain, holding none of these
deployments' logs, takes the Transparent Statement for #2, verifies the
Receipt against the Transparency Service's published key and the
inclusion proof, retrieves the Consent Evidence under access control,
and checks it against the committed `consent_rendering_hash`. The auditor
now knows that exact disclosure was registered at `t0` and has not since
been altered, dropped, or reordered, without trusting the Mission
Issuer's own records.

Two failures are distinct ({{verification-failures}}). If the retrieved
Consent Evidence hashes to a value other than the committed
`consent_rendering_hash`, the retained record was altered after
registration: an integrity failure, and the auditor rejects it. If the
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
({{I-D.draft-ietf-scitt-architecture}}). It also proves only that a
record was registered, not that the action the record describes occurred
or was authorized; that is the evidence's own semantics. And because
statements commit by hash, a Receipt without the retrievable evidence
proves only that some record was logged, not what it said.

# Conformance {#conformance}

A producer conforming to this profile MUST:

- register Mission evidence as Signed Statements with a detached hash
  commitment, never the evidence in the clear ({{registration}});
- set `sub` to the Mission feed by the fixed construction of {{feed}};
- set `iss` to its own issuer identifier, bound to the signing key; and
- register at least the approval event and every Mission lifecycle
  transition ({{registration}}).

A relying party conforming to this profile MUST:

- perform verification steps 1 through 5 of {{receipts}} before relying
  on a record as transparent;
- treat a signature, Receipt, inclusion-proof, or committed-hash
  mismatch as an integrity failure and reject the record; and
- treat unretrievable evidence as an audit failure, not as evidence of
  tampering ({{verification-failures}}).

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

# Privacy Considerations {#privacy-considerations}

A Transparency Service log is append-only and may be widely readable, so
nothing registered can be redacted later. A producer MUST NOT register
Mission evidence in the clear; it registers a hash commitment with a
detached payload ({{registration}}), and the evidence, which can carry
task descriptions, principals, and high-risk authority, is retained
separately under access control. Even the committed metadata leaks
information: the `sub` is a durable per-Mission correlator and the
registration times reveal a Mission's activity pattern. The `sub`
construction is fixed ({{feed}}) and does not expose the Subject
directly, so the concern is not Subject leakage but that the Mission's
durable identifier, its existence, and its registration cadence are
visible in the log. A deployment SHOULD weigh whether those are
sensitive, and whether the `origin` and `id` that compose the `sub`
reveal more than intended, before registering a Mission's evidence in a
shared or widely readable log.

# IANA Considerations {#iana}

This document makes no IANA request. It reuses the Signed Statement and
Receipt media types of the transparency substrate
({{I-D.draft-ietf-scitt-architecture}}) and the evidence media types of
the suite, and derives the `sub` by profile rather than registering a
new identifier.

--- back

# Acknowledgments
{:numbered="false"}

This document is part of the Mission-Bound Authorization for OAuth 2.0
work and profiles the SCITT architecture to make Mission evidence
transparent and independently verifiable.
