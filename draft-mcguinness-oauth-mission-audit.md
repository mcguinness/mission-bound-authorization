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
and `id` (for example, the `origin` URL with the `mission_id` as a path
or fragment). All evidence about one Mission therefore shares one `sub`
and forms one Transparency Service feed. An auditor retrieves a Mission's
complete, ordered, append-only evidence by that `sub`, and the
substrate's non-equivocation guarantee means the auditor and the
deployment see the same feed.

The `sub` MUST be derived deterministically from `origin` and `id` so
that independent producers writing evidence about the same Mission (the
Mission Issuer, a PDP, a harness) write to the same feed. The `sub` is a
correlator, not a credential; presenting it authorizes nothing
({{I-D.draft-mcguinness-oauth-mission}}).

# Receipts and Transparent Statements {#receipts}

On registration the Transparency Service returns a Receipt, a signed
inclusion proof ({{I-D.draft-ietf-scitt-architecture}}). The producer
SHOULD retain the Receipt with the evidence, or on the Mission record,
as a Transparent Statement (the Signed Statement augmented with its
Receipt). A relying party then verifies offline, without contacting the
producer or the service: it verifies the Signed Statement signature
against the producer's trust anchor, the Receipt signature against the
Transparency Service's, and the inclusion proof, and then retrieves the
evidence and checks it against the committed hash.

A deployment MAY register the same evidence with more than one
Transparency Service and retain multiple Receipts; a relying party that
distrusts one service can then rely on another, and equivocation by one
service is detectable against the others.

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

A producer conforming to this profile MUST register Mission evidence as
Signed Statements with a detached hash commitment, set `sub` to the
Mission per {{feed}}, and register at least the approval event and
lifecycle transitions. A relying party conforming to this profile MUST
verify a Transparent Statement per {{receipts}}, including checking the
retrieved evidence against the committed hash, before relying on it as
transparent.

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
registration times reveal a Mission's activity pattern. A deployment
SHOULD derive `sub` so it does not expose the Subject or task in the
clear, and SHOULD weigh whether a Mission's mere existence and cadence
are sensitive before registering its evidence in a shared log.

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
