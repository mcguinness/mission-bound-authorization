---
title: "Mission Approval Governance"
abbrev: "Mission Approval Governance"
category: std

docname: draft-mcguinness-mission-approval-governance-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - oauth
 - mission
 - agent
 - authorization
 - approval
 - governance
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-approval-governance.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  I-D.draft-mcguinness-mission-substrate:
    title: "Mission Substrate Requirements"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-substrate.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  RFC3339:
  RFC6838:
  RFC7515:
  RFC8259:
  RFC8785:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

informative:
  RFC9396:
  I-D.draft-mcguinness-oauth-mission-approval:
    title: "Mission Deferred Approval for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-approval.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-consent-evidence:
    title: "Mission Consent Evidence for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-consent-evidence.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-approval-revision:
    title: "Mission Approval Revision for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-approval-revision.html
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
  I-D.draft-mcguinness-mission-audit:
    title: "Mission Audit Transparency"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-audit.html
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

--- abstract

Mission-Bound Authorization records exactly one accountable Approver
per Mission and defers approval-authority provenance to a governance
layer. This document defines that layer's record: the Approval
Governance Record, an issuer-retained, issuer-signed record of the
policy, assertions, and evaluation standing behind an approval event.
It gives an estate first-class, auditable answers to who approved,
under which authority, and why the decision satisfied governance,
without adding any wire artifact. The record never appears on
tokens, protocol messages, or enforcement projections, and the
Mission record's single accountable Approver is unchanged.

--- middle

# Introduction

The issuance profile {{I-D.draft-mcguinness-oauth-mission}} records
one accountable Approver and defers multi-party approval and
approval-authority provenance to a governance layer. An enterprise
review surface is often that governance layer: a decision may
involve several principals, a threshold or separation-of-duty rule,
and a delegation-of-authority policy, and an auditor later needs to
prove not only who approved but under which authority the approval
was valid. This document defines the Approval Governance Record
(AGR) as governance evidence with teeth: where it is recorded, it
participates in whether the Mission activates, so its assertions
carry authentication and binding requirements, and its committed
form is signed and immutable.

Before commitment, the record is part of the approval decision
itself: an assertion that fails authentication, event binding, or
policy authorization MUST NOT contribute, and a record that cannot be
evaluated or persisted MUST prevent activation. After commitment, the
record is evidence: immutable, signed, and consumed by audit, never
by enforcement.

# Status: An Optional Extension {#optional-status}

This document is optional. A deployment that records nothing beyond
the Mission record's accountable `approver` is fully conformant to
the issuance profile and unaffected by this document. Profiles MAY
require this record; the Enterprise Mission Authority Profile does
so under its recording triggers
({{I-D.draft-mcguinness-mission-authority-server}}).

This document is ceremony-independent: it applies to synchronous
approval, deferred approval
({{I-D.draft-mcguinness-oauth-mission-approval}}), and the standalone
Mission Authority Server's native asynchronous approval alike, and
depends on no deferral substrate.

# Conventions and Definitions {#conventions-and-definitions}

{::boilerplate bcp14-tagged}

This document uses JSON {{RFC8259}} as the data model for the
Approval Governance Record. JCS canonicalization {{RFC8785}} applies
wherever this document computes a digest or a signing input, under
the canonicalization rules of {{I-D.draft-mcguinness-oauth-mission}};
this document does not define a second canonicalization.

A digest is encoded in the integrity-anchor encoded form of
{{I-D.draft-mcguinness-oauth-mission}}: the `sha-256:` prefix
followed by the base64url, no-padding encoding of the digest. This
document defines no digest algorithm of its own. Its two digests are
classified under the substrate's default commitment construction,
which this document imports normatively
({{I-D.draft-mcguinness-mission-substrate}}):
`approval_policy.digest` is an envelope anchor, and the record
digest ({{envelope}}) is a canonical-object digest.

The terms Mission, Mission Issuer, Approver, approval event,
`approval_event_id`, `intent_hash`, and `authority_hash` are used as
defined in {{I-D.draft-mcguinness-oauth-mission}}.

Approval Governance Record (AGR):
: The record this document defines: the policy, assertions, and
  evaluation standing behind one approval event ({{record}}).

Assertion:
: One principal's authenticated decision statement carried in an AGR
  ({{record}}).

Evaluation:
: The issuer's determination of whether the recorded assertions
  satisfy the referenced approval policy ({{record}}).

Recording trigger:
: A condition under which a profile requires this record for an
  approval event ({{triggers}}).

# Relationship to the Issuance Profile {#issuance-relationship}

The Mission record carries exactly one accountable `approver`, and
this document does not change that: the accountable Approver remains
the only principal any downstream projection, token, or enforcement
point consumes. The record captures the standing behind that
approval, never a second authorization surface visible outside the
issuer.

`approval_event_id` joins the record to the approval event and to
the Mission record it governs
({{I-D.draft-mcguinness-oauth-mission}}). The record never appears on
tokens or in any protocol message; it is issuer-retained
control-plane state.

# The Approval Governance Record {#record}

An Approval Governance Record is a JSON object with these members,
plus the integrity `envelope` {{envelope}} defines.

`approval_event_id`:
: REQUIRED. A string. The approval event's identifier, equal to the
  Mission record's `approval_event_id`
  ({{I-D.draft-mcguinness-oauth-mission}}).

`mission`:
: REQUIRED. An object binding the record to the approved Mission:
  `issuer` (the Mission Issuer), `intent_hash`, and `authority_hash`,
  each equal to the committed Mission record member of the same
  name. A record whose binding does not match the Mission record it
  is retained with is invalid.

`approval_policy`:
: REQUIRED. An object identifying the governing
  delegation-of-authority policy: `id` (an identifier), `version` (a
  string), and `digest` (an integrity anchor over the retained policy
  snapshot, in the encoded form {{conventions-and-definitions}}
  fixes). The digest preimage is the issuance profile's
  integrity-anchor envelope ({{I-D.draft-mcguinness-oauth-mission}})
  with `typ` `mission-approval-policy`, `iss` the Mission issuer, and
  `value` an object of `content_type` (the snapshot's media type) and
  `content` (the base64url, no-padding encoding of the snapshot
  bytes), canonicalized with JCS {{RFC8785}}: the `typ`
  domain-separates this anchor from every other anchor in the family,
  and the issuer binding prevents cross-issuer replay. The snapshot
  bytes and their media type, or the referenced policy version they
  represent, MUST be retained for the Mission's audit horizon
  ({{I-D.draft-mcguinness-oauth-mission}}), so an independent auditor
  reproduces the digest exactly and re-checks the evaluation against
  the policy that governed it. Threshold, quorum, veto, and separation-of-duty semantics live
  in the referenced policy; any human-readable summary of them in
  deployment tooling is advisory and carries no semantics in this
  record.

`assertions`:
: REQUIRED. An array of one or more decision assertions. Each
  carries:

    `assertion_id`:
    : REQUIRED. A string, unique within the record.

    `principal`:
    : REQUIRED. An object with `iss` and `sub`.

    `kind`:
    : REQUIRED. A string, one of `human`, `service`, or `policy`.

    `decision`:
    : REQUIRED. A string, one of `approve` or `deny`.

    `decided_at`:
    : REQUIRED. An RFC 3339 {{RFC3339}} timestamp.

    `authority`:
    : REQUIRED. A reference to the provenance under which this
      principal was authorized to decide. For a `human` assertion,
      the authentication context of the assertion. For a `policy`
      assertion, the deciding policy's identifier and version: the
      family's provenance chain for non-human approval, in which the
      policy approves the instance because a human approved the
      policy.

    `reason`:
    : OPTIONAL. A string.

`evaluation`:
: REQUIRED. An object recording the outcome: `decision` (a string,
  `approved`, the only value a committed record carries, since a
  record exists only for an approval that committed,
  {{atomic-commitment}}), `evaluated_at` (an RFC 3339 timestamp),
  and `contributing` (an array of the `assertion_id` values the
  evaluation relied on).

`envelope`:
: REQUIRED. An object. Integrity protection over the members above,
  in the form {{envelope}} defines.

~~~ json
{
  "approval_event_id": "ape_8K2nP4qV9rL3tY6sB1z",
  "mission": {
    "issuer": "https://as.example.com",
    "intent_hash":
      "sha-256:wQ7p4LHnX9Md0LqJ6sZJ8b8mZ3rN2xT5pV4lE6sQqYY",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ"
  },
  "approval_policy": {
    "id": "dlg-matrix",
    "version": "v7",
    "digest":
      "sha-256:OAbEIh2DTYUVP7DjRhHct4aapsT8PybZq2ILdut9UP0"
  },
  "assertions": [
    { "assertion_id": "ast_1",
      "principal": { "iss": "https://login.example.com",
        "sub": "manager@example.com" },
      "kind": "human", "decision": "approve",
      "decided_at": "2026-09-30T16:58:11Z",
      "authority": { "role": "finance-manager" } },
    { "assertion_id": "ast_2",
      "principal": { "iss": "https://as.example.com",
        "sub": "policy:finance-charter" },
      "kind": "policy", "decision": "approve",
      "decided_at": "2026-09-30T16:58:12Z",
      "authority": { "policy_id": "dlg-matrix", "version": "v7",
        "approved_by": { "iss": "https://login.example.com",
          "sub": "cfo@example.com" } } }
  ],
  "evaluation": {
    "decision": "approved",
    "evaluated_at": "2026-09-30T16:58:13Z",
    "contributing": ["ast_1", "ast_2"]
  },
  "envelope": {
    "format": "jws-compact",
    "value": "eyJhbGciOiJFUzI1NiIsImtpZCI6ImFzLWtleS0y..."
  }
}
~~~

The Mission record's accountable `approver` in this example is
`manager@example.com`; `ast_1` is that principal's own `approve`
assertion, satisfying the accountable-approver rule of
{{assertion-requirements}} directly. `ast_2` is a `policy` assertion
carrying its own provenance chain, recorded alongside rather than in
place of the accountable approver's assertion. The `envelope`
member's `value` is the JWS whose payload is the JCS canonical bytes
of this object with `envelope` itself removed ({{envelope}}).

# Assertion Requirements {#assertion-requirements}

These rules are the record's security core.

- Every assertion that contributes to the evaluation MUST be
  authenticated: a `human` assertion with the authentication the
  issuance profile requires of an Approver at an approval event, a
  `service` or `policy` assertion through an integrity-protected
  channel or signature the issuer verifies.
- Every assertion MUST be bound to this approval event: an assertion
  is made against this `approval_event_id` and this `authority_hash`,
  and an assertion captured for one event MUST NOT be replayed into
  another.
- Every contributing assertion MUST be policy-authorized: the issuer
  verifies the asserting principal was eligible to assert under the
  referenced `approval_policy` version before counting it.
- Denials and vetoes MUST be recorded: an assertion set that omits a
  negative assertion misrepresents the decision.
- Exactly one assertion MUST match the Mission record's accountable
  `approver` and carry an `approve` decision; the record supports
  the approval it claims to govern or it does not commit. A
  policy-authority Approver satisfies this with a `policy` assertion
  carrying its provenance chain.
- An assertion that fails authentication, event binding, or policy
  authorization MUST NOT contribute to the evaluation and MUST NOT
  be counted toward any policy rule.

# Evaluation and Atomic Commitment {#atomic-commitment}

Where a deployment records the Approval Governance Record for an
approval, the record and the Mission are one commit: the issuer
evaluates the assertions under the referenced policy, and the
Mission record MUST NOT be created `active` unless the evaluation's
`decision` is `approved` and the signed record persists atomically
with the Mission's creation. Failure to authenticate the
contributing assertions, to complete the evaluation, or to persist
the record MUST prevent activation; there is no Mission whose
governance record was meant to exist and does not. A governance
evaluation that denies creates no Mission and no committed record:
negative assertions retained inside a committed record document
dissent ({{assertion-requirements}}), and a wholly declined
approval's evidence surface is consent evidence's declined outcome
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}), which
exists without a Mission record. The issuer signs
the evaluated record ({{envelope}}) and persists the signed form in
the same commit as the Mission's creation; signing follows
evaluation and precedes persistence, never the reverse.

A committed record is immutable. A subsequent governance action, a
re-review or an incident finding, is a new record about a new event,
never an edit.

# Envelope and Verification {#envelope}

An Approval Governance Record carries its integrity protection in an
`envelope` member: REQUIRED, an object with `format` (a string,
required) and `value` (a string, required). The default `format` is
`jws-compact`, a JWS Compact Serialization {{RFC7515}} over the JCS
{{RFC8785}} canonical bytes of the record with the `envelope` member
removed, signed by the Mission Issuer under a key resolvable in its
published key material. The signed record, `envelope` included, is
the retained, registrable form.

A verifier MUST perform the following steps, in order, and MUST NOT
treat a record as verified if any step fails:

1. Resolve the Mission Issuer's signing key from the JWS protected
   `kid` in its published key material.
2. Verify the JWS signature and protected header against that key.
3. Compute the JCS canonical bytes of the outer record with the
   `envelope` member removed.
4. Require byte-for-byte equality between the decoded JWS payload
   and the canonical bytes of step 3, rejecting the record on any
   difference. The signature authenticates only its own embedded
   payload; a record that differs from that payload is
   unauthenticated regardless of whether the signature itself
   verifies.
5. Validate the mission binding of {{record}} against the Mission
   record it is retained with.

The JWS protected header MUST carry a `kid` resolvable in the Mission
Issuer's published key material and a `typ` of
`application/mission-approval-governance+json` ({{iana}}); a verifier
MUST reject a JWS whose protected `typ` is not this value. This
document defines only the `jws-compact` format; an implementation
MUST reject an envelope whose `format` is unsupported rather than
accepting it unverified.

The **record digest** is the digest, in the encoded form
{{conventions-and-definitions}} fixes, over the JCS {{RFC8785}}
canonical bytes of the complete record, `envelope` included. It is
the one byte sequence every external binding names: audit
registration hashes exactly these bytes ({{audit-evidence}}), and
consent evidence's `approval_governance_digest` equals exactly this
value ({{consent-evidence-relationship}}).

# Recording Triggers {#triggers}

Defined here so a profile cites one list. The record is REQUIRED for
an approval event when any of the following holds:

- the Mission record's `approver` differs from its `subject`;
- more than one principal contributes to the decision;
- a non-human assertion contributes to the decision;
- a threshold, veto, or separation-of-duty rule is evaluated; or
- validating any assertion requires authority standing outside the
  Mission record.

Direct self-approval by one authenticated human is the degenerate
case: the Mission record already carries it completely, and no
record is required.

# Consent Evidence Relationship {#consent-evidence-relationship}

Where both are recorded, the AGR is authoritative for
approval-governance facts, and consent evidence presents a
deliberately partial view of it
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}). Agreement
is testable, member by member:

- Each `co_approvals` entry MUST correspond to exactly one `human`
  assertion in the record with the same `principal`, the entry's
  decision equal to the assertion's `decision`, and the entry's
  timestamp equal to the assertion's `decided_at`. Omitting an
  assertion is permitted; an entry with no corresponding assertion,
  or one that alters a decision or time, is an integrity failure.
  `service` and `policy` assertions are governance inputs, never
  consent events, and are never presented as co-approvals.
- The consent evidence `approver` MUST equal the `principal` of the
  record's accountable assertion ({{assertion-requirements}}).
- `approval_authority`, when present, MUST equal
  `approval_policy.id`; `approval_policy_version`, when present,
  MUST equal `approval_policy.version`.
- `approval_governance_digest`, when present, MUST equal the record
  digest ({{envelope}}).

The AGR governs on any disagreement.

Where a deferred approval revises under Mission Approval Revision
({{I-D.draft-mcguinness-oauth-mission-approval-revision}}) and the
deployment records consent evidence, each `revision_required` outcome
produces a `narrowed` consent-evidence decision with no corresponding
record: no Mission yet exists for the atomic commitment rule
({{atomic-commitment}}) to attach to. Where consent evidence is
recorded, it owns the narrowing history, through its `narrowed`
entries and `predecessor_intent_hashes`. Where an AGR is recorded for
the final approval, it owns the final approval-governance facts. This
is a deliberate artifact separation, not an authority conflict.

# Boundaries {#boundaries}

The record governs the Mission approval event; an action-time
approval under the runtime profile's re-evaluation surfaces
({{I-D.draft-mcguinness-mission-runtime}}) is a different layer and
never joins this record.

OAuth standardizes the requested and granted authorization data, not
an organization's internal approval provenance ({{RFC9396}} takes the
same boundary for rich authorization requests); this record therefore
stays off protocol messages and out of enforcement projections,
matching the issuance profile's control-plane discipline.

# Mission Evidence {#audit-evidence}

The AGR is registrable Mission evidence under the audit
transparency profile's evidence-type pattern
({{I-D.draft-mcguinness-mission-audit}}): canonical bytes are the
JCS canonical bytes of the complete record, `envelope` included, the
record-digest preimage ({{envelope}}); `payload-preimage-content-type` is
`application/mission-approval-governance+json`; the authoritative
producer is the Mission `issuer`. Registration is optional
transparency hardening; retention and immutability do not depend on
it.

# Security Considerations {#security-considerations}

## Forged or Padded Assertions

A forged or padded assertion is an authorization attack before
commitment, not an audit defect: the assertion requirements of
{{assertion-requirements}} are the control, and a deployment that
records assertions without authenticating them has built an approval
bypass rather than an evidence trail.

## Policy Substitution

Without `approval_policy.digest` and its retention, a later reading
cannot prove which policy governed the evaluation. The digest and
the audit-horizon retention of {{record}} are the control.

## Manufactured Accountability

The accountable-approver assertion rule of
{{assertion-requirements}} prevents a set of service and policy
assertions from claiming a Mission whose named Approver never
asserted anything.

## Immutability Witness

The issuer-signed envelope of {{envelope}} makes post-commit
tampering detectable. Audit registration ({{audit-evidence}})
additionally bounds issuer-side substitution, since a registered
record's later alteration diverges from its receipt.

## Issuer Key Compromise

This document inherits the issuance profile's key-material
considerations. A compromised Mission Issuer signing key can mint a
plausible record; audit registration
({{I-D.draft-mcguinness-mission-audit}}) is the existence bound, not
a substitute for key custody.

# Privacy Considerations

Assertion principals and decision times are PII about reviewers. The
record is control-plane state retained by the issuer, never
disclosed on wire surfaces, and access to a retained record follows
the issuer's audit-log discipline for approval-event records
({{I-D.draft-mcguinness-oauth-mission}}).

# IANA Considerations {#iana}

## Media Type Registration

IANA is requested to register one media type per {{RFC6838}}.

### application/mission-approval-governance+json

- Type name: application
- Subtype name: mission-approval-governance+json
- Required parameters: none
- Optional parameters: none
- Encoding considerations: binary; JSON encoded in UTF-8
- Security considerations: see {{security-considerations}}
- Interoperability considerations: see this document
- Published specification: this document
- Applications that use this media type: Mission-Bound Authorization
  issuers and audit deployments
- Fragment identifier considerations: same as for `application/json`
- Additional information:
  - Deprecated alias names for this type: none
  - Magic number(s): none
  - File extension(s): `.json`
  - Macintosh file type code(s): TEXT
- Person & email address to contact for further information:
  Karl McGuinness <public@karlmcguinness.com>
- Intended usage: COMMON
- Restrictions on usage: none
- Author: IETF
- Change controller: IETF

# Conformance {#conformance}

A **Recording Issuer** MUST:

- authenticate, event-bind, and policy-authorize every contributing
  assertion ({{assertion-requirements}});
- record denials;
- include the accountable-approver assertion;
- evaluate under the retained policy version;
- commit the record atomically with Mission creation and let failure
  prevent activation ({{atomic-commitment}});
- sign the committed record and keep it immutable
  ({{envelope}}); and
- retain the record and the referenced policy for the Mission's
  audit horizon ({{I-D.draft-mcguinness-oauth-mission}}).

A **Relying Auditor** MUST verify the envelope by byte equality, MUST
validate the mission binding, and MUST obtain the retained policy
version before treating the evaluation as re-checked
({{envelope}}).

--- back

# Acknowledgments
{:numbered="false"}

This document extracts the experimental approval-provenance record
that Mission Deferred Approval first sketched into a standalone
companion, and reshapes it so its assertions carry the
authentication, binding, and policy-authorization requirements that
governance evidence with teeth requires. The author thanks the
Mission-Bound Authorization
implementer community for feedback.
