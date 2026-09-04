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
  I-D.draft-mcguinness-oauth-mission-progressive:
    title: "Mission Progressive Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-progressive.html
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
  I-D.draft-mcguinness-mission-metering:
    title: "Mission Consumption Metering"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-metering.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-template:
    title: "Mission Template for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-template.html
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

An authority-bearing binding of the Mission model records one
accountable Approver and defers multi-party approval and
approval-authority provenance to a governance layer
({{I-D.draft-mcguinness-oauth-mission}} states the rule for the
OAuth binding, whose record members this document's binding rules
consume). An enterprise review surface is often that governance
layer: a decision may involve several principals, a threshold or
separation-of-duty rule, and a delegation-of-authority policy, and an
auditor later needs to prove not only who approved but under which
authority the approval was valid.

This document defines the Approval Governance Record (AGR) as
governance evidence with teeth: where it is recorded, it participates
in whether the Mission activates, so its assertions carry
authentication and binding requirements, and its committed form is
signed and immutable.

Before commitment, the record is part of the approval decision
itself: an assertion that fails authentication, event binding, or
policy authorization MUST NOT contribute, and a record that cannot be
evaluated or persisted MUST prevent activation. After commitment, the
record is evidence: immutable, signed, and consumed by audit, never
by enforcement.

# Status: An Optional Extension {#optional-status}

This document is optional. A deployment that records nothing beyond
the Mission record's accountable `approver` is fully conformant to
its Mission binding and unaffected by this document. Profiles MAY
require this record; the Enterprise Mission Authority Profile does
so under its recording triggers
({{I-D.draft-mcguinness-mission-authority-server}}).

This document is ceremony-independent: it applies to synchronous
approval, deferred approval
({{I-D.draft-mcguinness-oauth-mission-approval}}), and the standalone
Mission Authority Server's native asynchronous approval alike, and
depends on no deferral substrate.

<!-- family-status: BEGIN (generated from family-manifest.json; exact-matched by scripts/check-family-manifest.mjs) -->
Role: companion. Spec maturity: experimental. Maintenance: active.
Implementation: 15 conformance rows in conformance-manifest.json (6 tested, 9 todo).
Adopt when: Approval authority itself needs authenticated, policy-backed provenance.
Requires: Mission Substrate Requirements.
Also requires, conditionally: Mission Progressive Authorization for OAuth 2.0 (when the Approval Context Manifest is computed for a Mission whose record carries a Progressive ceiling).
<!-- family-status: END -->

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

The terms Mission, Mission Issuer, Approver, approval event, Mission
Intent, `approval_event_id`, `intent_hash`, and `authority_hash`
are used as defined in
{{I-D.draft-mcguinness-oauth-mission}}.

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
control-plane state. Where the governed Mission populates
`approval_basis.adjudication`
({{I-D.draft-mcguinness-oauth-mission}}, Section "Role Mapping") and
this record exists, `adjudication.governance_record` is `true` and
`kind` equals this record's accountable assertion's own mechanism,
never a value that names this record itself, and never a flattening
of its assertion set into a single principal.

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

`approval_context_commitment`:
: OPTIONAL. A string. The Approval Context Commitment over the
  governed Mission's immutable creation facts
  ({{approval-context-commitment}}), in the encoded form
  {{conventions-and-definitions}} fixes. It is a member of this
  record, never of the Mission record: the profile adds no Mission
  record member ({{approval-context-computation}}). An issuer that
  records it computes it in the same commit that creates the Mission
  and persists this record, before the record is signed
  ({{atomic-commitment}}), so the signed payload commits to it. The
  `mission` member above carries no Mission `id`, so a verifier
  recomputes this value from the Mission record this record is
  retained with, the record the mission binding check already
  resolves ({{envelope}}, step 5), and rejects the reference on a
  mismatch ({{approval-context-computation}}). Its presence is what
  lets this record and another authenticated artifact disclosing the
  same commitment be matched to one approval transaction without
  either re-deriving the other's fields.

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
      assertion, the deciding policy's identifier and version, and
      `approved_at`: the family's provenance chain for non-human
      approval, in which the policy approves the instance because a
      human approved the policy.

      `approved_at` is an RFC 3339 timestamp: the human approval
      instant of that exact policy version, not the assertion
      instant. `decided_at` records when the policy asserted;
      `approved_at` records when a human approved the version it
      asserts under. The issuer MUST verify `approved_at` from
      retained, authenticated governance state for the named
      `policy_id` and `version`; it MUST NOT accept `approved_at` as
      the assertion's own uncorroborated clock value
      ({{policy-approval-recency}}).

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
          "sub": "cfo@example.com" },
        "approved_at": "2026-09-15T09:00:00Z" } }
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
  carrying its provenance chain, subject to the high-risk-class
  restriction of {{policy-approval-recency}}. A Mission rooted in a
  named standing-consent `approval_basis`
  ({{I-D.draft-mcguinness-oauth-mission}}) satisfies this rule
  through that record instead of a contributing assertion:
  `consent_principal` (equal to `approver`), `root_commitment`, and
  `approved_at`, already fixed at the approval event and immutable,
  stand in place of a matching assertion, subject to the same
  high-risk-class restriction. No assertion is fabricated in the
  name of the activating policy or the requesting actor to stand in
  for a fresh human decision that did not occur.
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

Where the record carries `approval_context_commitment` ({{record}}),
the issuer computes it in this same commit, from the Mission record
being created, and before signing. A value computed after the commit
is not covered by the record's signature and MUST NOT be added to a
committed record.

A committed record is immutable. A subsequent governance action, a
re-review or an incident finding, is a new record about a new event,
never an edit.

# Policy-Approval Recency {#policy-approval-recency}

This section bounds staleness on the AGR `policy` assertion path: it
governs a `policy` assertion's `authority.approved_at` and the
`kind` of the accountable-approver's assertion. It does not apply to
a `human` assertion, whose `decided_at` is the approval instant
itself.

A Recording Issuer that admits `policy` assertions MUST declare a
maximum policy-approval age per consequence class (a **recency
ceiling**) and a bounded clock-skew allowance, and MAY declare, per
class, an **exception** admitting a `policy` assertion as the
accountable approver's assertion for that class, each exception
carrying its own maximum age. The ceiling, the skew allowance, and
any exception MUST be part of the retained `approval_policy` snapshot
that `approval_policy.digest` commits ({{record}}), or a separately
versioned declaration committed from that snapshot. A mutable,
out-of-band deployment statement MUST NOT serve this role: it would
make the evaluation impossible to reproduce, contrary to the promise
of {{record}} that the retained policy lets an auditor re-run the
decision.

At evaluation, the issuer MUST classify the committed Mission's
consequence classes from the derived Authority Set and from any
consumption bound the Mission Intent carries
({{I-D.draft-mcguinness-mission-metering}}). The issuer MUST select,
across every class either source carries, the strictest maximum age
that applies, accounting for any declared exception. This is a
property of the whole committed Mission the record's
`mission.authority_hash` and `mission.intent_hash` bind to
({{record}}), never of one assertion or entry in isolation.

For each `policy` assertion the evaluation would count toward the
applicable maximum, the issuer:

- MUST verify `authority.approved_at` from retained, authenticated
  governance state for the exact `policy_id` and `version` the
  assertion names;
- MUST measure the assertion's age as `evaluation.evaluated_at` minus
  `authority.approved_at`, using the atomic-commitment instant
  ({{atomic-commitment}});
- MUST enforce `authority.approved_at` <= `decided_at` <=
  `evaluation.evaluated_at`, subject to the declared clock-skew
  allowance; and
- MUST reject the assertion if `authority.approved_at` or
  `decided_at` is later than the issuer's own clock at evaluation,
  beyond that allowance.

A `policy` assertion whose age exceeds the applicable maximum, or
whose ordering the previous paragraph does not admit, fails
policy-authorization under {{assertion-requirements}}: the issuer
MUST NOT count it toward the evaluation, and by
{{atomic-commitment}} the Mission MUST NOT be created `active` on an
evaluation that depended on it. An `evaluation.evaluated_at` later
than the issuer's own clock, beyond the declared allowance, is a
defect of the record rather than of one assertion: the evaluation
MUST NOT be treated as complete, and by {{atomic-commitment}} the
Mission MUST NOT be created `active` on it.

This is issuance-time eligibility. It determines whether a Mission
activates and does not reach back into a Mission already `active`:
that Mission's governing policy approval was measured fresh at its
own approval event, and a later change to the ceiling, the exception,
or the policy's freshness does not narrow or terminate it.

Four conditions are the high-risk classes the issuance profile
defines: irreversible action, external commitment, privileged
administration, and a consumption bound
({{I-D.draft-mcguinness-oauth-mission}}). Where the committed
Mission's derived Authority Set or Mission Intent
({{I-D.draft-mcguinness-mission-metering}}) carries one, the
assertion satisfying the accountable-approver rule of
{{assertion-requirements}} MUST be `kind: human`, unless a committed,
class-named exception under this section admits `kind: policy` for
that class.

The same default binds a Mission whose accountable-approver rule is
satisfied through its own `approval_basis` record rather than an
assertion ({{assertion-requirements}}): recording an AGR for such a
Mission carrying one of the four classes requires a committed,
class-named exception under this section; absent it, the record MUST
NOT be created and, by {{atomic-commitment}}, the Mission MUST NOT be
created `active`.

Approval Governance is an optional extension
({{optional-status}}); the rules of this section are a conservative
default of that profile, not a family-wide guarantee, and a
deployment that records no Approval Governance Record is unbounded
by them. `kind: human` is not by itself an assurance property: the
authentication-strength, rendering, and accountable-principal
requirements the issuance profile and {{assertion-requirements}}
otherwise impose still carry that property; this section only
decides which assertion kind MUST be present.

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
Issuer's published key material, a `typ` of
`application/mission-approval-governance+jws`, and a `cty` of
`application/mission-approval-governance+json` ({{iana}}); a verifier
MUST reject a JWS whose protected `typ` and `cty` are not exactly
this pair ({{RFC7515}}, Sections 4.1.9 and 4.1.10). This
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
  record's accountable assertion ({{assertion-requirements}}); for a
  standing-consent Mission whose accountable-approver rule is
  satisfied by `approval_basis` rather than an assertion, it MUST
  equal `approval_basis.consent_principal` instead.
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

# Approval Context Commitment {#approval-context-commitment}

This section defines an OPTIONAL profile: one commitment over a
Mission's immutable creation facts, so an artifact that authenticates
a reference to it can be checked against another authenticated
artifact's reference to the same Mission without either re-deriving
the other's fields. Adopting this profile is independent of whether
a deployment records an Approval Governance Record for a given
Mission.

## Manifest {#approval-context-manifest}

The **Approval Context Manifest** is a closed, enumerated v1 object
built from Mission Record members
({{I-D.draft-mcguinness-oauth-mission}}). Its members:

| Member | Source | Presence |
|---|---|---|
| `issuer` | Mission Record `issuer` | always |
| `id` | Mission Record `id` | always |
| `intent_hash` | Mission Record `intent_hash` | always |
| `proposal_hash` | Mission Record `proposal_hash` | iff the Mission Record carries it |
| `authority_hash` | Mission Record `authority_hash` | always |
| `ceiling_hash` | Progressive's `ceiling_hash` anchor ({{I-D.draft-mcguinness-oauth-mission-progressive}}) | iff the Mission Record carries it |
| `subject` | Mission Record `subject` | always |
| `approver` | Mission Record `approver` | always |
| `client_id` | Mission Record `client_id` | always |
| `created_at` | Mission Record `created_at` | always |
| `expires_at` | Mission Record `expires_at` | always |
| `approval_basis` | Mission Record `approval_basis`, verbatim | always |
| `authority_source` | Mission Record `authority_source`, verbatim | always |
| `policy_version` | Mission Record `policy_version` | always |
| `approval_event_id` | Mission Record `approval_event_id` | always |
| `submission_evidence_commitment` | {{approval-context-construction}} | iff the Mission Record carries `submission_evidence` |
{: title="Approval Context Manifest v1 members"}

The presence of every conditional member MUST be a deterministic
function of the Mission Record alone, never of which companion
profiles a deployment runs: two parties holding the same record
compute the same manifest.

`ceiling_hash` is the manifest's fourth anchor alongside `intent_hash`,
`proposal_hash`, and `authority_hash`: the manifest MUST include
`ceiling_hash` when the Mission Record carries one and MUST omit it
when the Mission Record carries none. This member's construction and
semantics are defined by the Progressive profile
({{I-D.draft-mcguinness-oauth-mission-progressive}}), a normative
reference of this document for that reason; this section imports its
`ceiling_hash` definition without redefining it, and adopting this
Approval Context Commitment profile does not by itself require
adopting Progressive ({{optional-status}}).

The manifest excludes the Mission Record's one mutable member,
`state`, and every value that is not itself a member of the
immutable record: a running derivation count, and a containment or
discharge state a companion profile tracks outside the record. This
is not a separate exclusion rule; it follows from building the
manifest from Mission Record members only.

## Construction {#approval-context-construction}

The manifest is an envelope anchor under the issuance profile's
commitment mechanisms, which this document imports normatively
({{I-D.draft-mcguinness-oauth-mission}}): `typ` is
`mission-approval-context-v1`, `iss` is the Mission `issuer`, and
`value` is the manifest object of {{approval-context-manifest}}. The
result, `approval_context_commitment`, is one `sha-256:`-prefixed
string.

`submission_evidence_commitment` is a second envelope anchor under
the same mechanism, present only when the Mission Record carries
`submission_evidence`: `typ` is `mission-submission-evidence-v1`,
`iss` is the Mission `issuer`, and `value` is the recorded
`submission_evidence` array exactly as retained, preserving its
canonical element order ({{I-D.draft-mcguinness-oauth-mission}}).

## Computation and Versioning {#approval-context-computation}

An issuer computes `approval_context_commitment` on demand from the
Mission's immutable creation facts, fixed at the approval event
({{I-D.draft-mcguinness-oauth-mission}}). This document adds no
Mission Record member for it; an Approval Governance Record MAY carry
it as a member of its own signed record ({{record}}), which is a
disclosure of the computed value, not a second place the Mission
record holds it. A deployment MAY cache the computed
value; a cached value is derived state and MUST NOT be treated as
authoritative where it disagrees with a fresh computation from the
record.

A verifier that recomputes `approval_context_commitment` from the
Mission's immutable creation facts and obtains a value different from
the one an artifact discloses MUST reject that artifact's reference
as invalid. The recompute always uses this document's fixed `typ`,
`mission-approval-context-v1`; a value some other party committed
under a different `typ` recomputes to a different digest under this
rule and is rejected the same way ({{approval-context-vectors}},
vector 6).

The member list of {{approval-context-manifest}} is closed for
`mission-approval-context-v1`. Adding, removing, or redefining a
member, or changing how `submission_evidence_commitment` is
constructed, MUST use a new `typ`, never a silent reinterpretation of
this one.

## Limits {#approval-context-limits}

Reusing the issuance profile's commitment mechanisms supplies
canonicalization and algorithm identification and agility. It
supplies nothing else:

- No authenticity. The commitment is an unkeyed digest over Mission
  Record fields held under the same trust as the record itself. An
  issuer that can rewrite the record can recompute a matching
  commitment; authentication comes entirely from the signature of
  whichever artifact discloses the commitment, never from the digest
  construction.
- No approval-time existence. A matching commitment shows the
  disclosed facts are internally consistent with the retained
  record. It does not show the facts were true, or that an approval
  occurred, at the time claimed.
- No selective disclosure. The commitment is a flat digest over the
  complete manifest object; proving anything about one member
  requires disclosing the whole object.

## Carriage {#approval-context-carriage}

`approval_context_commitment` MAY appear as a signed member of an
artifact that already authenticates a reference to the Mission, for
example this document's own Approval Governance Record
({{record}}) or a Consent Evidence object
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}), or under
an introspection caller's member-scoped disclosure privilege, the
same privilege that already gates `proposal_hash`
({{I-D.draft-mcguinness-oauth-mission}}).

`approval_context_commitment` MUST NOT be carried on a Mission-bound
access token's baseline `mission` claim
({{I-D.draft-mcguinness-oauth-mission}}) or on a credential-bound
Mission descriptor a companion profile mints for correlation, for
example the Mission Authority Server's Join Assertion
({{I-D.draft-mcguinness-mission-authority-server}}): each already
fixes its own minimal member set, and this commitment is correlation
and evidence metadata, never authority.

## Test Vectors {#approval-context-vectors}

These non-normative vectors let an implementation verify its manifest
and commitment computation byte for byte, the same discipline as the
issuance profile's own Integrity Anchor Test Vectors
({{I-D.draft-mcguinness-oauth-mission}}). All use the issuer
`https://as.example.com`. Every canonical-bytes block is the exact
JCS {{RFC8785}} output, shown wrapped only for layout; remove the
layout line breaks, adding no characters, to recover the single-line
canonical form.

Vector 2 below reuses, byte-exact, the always-present manifest
members from the issuance profile's own canonical Worked Example
Mission Record ({{I-D.draft-mcguinness-oauth-mission}}), including
its `proposal_hash`, per that document's rule that an extending
example must either reproduce the recorded objects byte-exactly or
state its divergence. Vectors 1, 3, and 4 are hypothetical variants
of that same Mission (same `id`, `intent_hash`, and `authority_hash`)
that diverge in exactly one respect each, stated at each vector: this
lets three different `approval_context_commitment` values legitimately
exist for the one Mission `id` across the set, each correct for the
variant it names, never for the others.

The always-present members, reused unchanged across every vector:

~~~ json
{
  "issuer": "https://as.example.com",
  "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
  "intent_hash":
    "sha-256:wQ7p4LHnX9Md0LqJ6sZJ8b8mZ3rN2xT5pV4lE6sQqYY",
  "authority_hash":
    "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ",
  "subject": { "iss": "https://idp.example.com",
    "sub": "user_3p2q8mN1a0kV7tR" },
  "approver": { "iss": "https://idp.example.com",
    "sub": "user_3p2q8mN1a0kV7tR" },
  "client_id": "s6BhdRkqt3",
  "created_at": "2026-10-15T14:32:11Z",
  "expires_at": "2026-12-31T23:59:59Z",
  "approval_basis": {
    "type": "direct",
    "consent_principal": { "iss": "https://idp.example.com",
      "sub": "user_3p2q8mN1a0kV7tR" },
    "activation": { "approval_event_id": "ape_8K2nP4qV9rL3tY6sB1z" },
    "activation_actor": { "iss": "https://idp.example.com",
      "sub": "user_3p2q8mN1a0kV7tR" },
    "adjudication": { "kind": "human" },
    "root_commitment":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ"
  },
  "authority_source": { "type": "user_delegated" },
  "policy_version": "deploy-policy:v17",
  "approval_event_id": "ape_8K2nP4qV9rL3tY6sB1z"
}
~~~

**Vector 1: base manifest.** Diverges from the canonical Mission by
carrying no `proposal_hash`: this variant never recorded a
`proposed_authority` distinct from its Authority Set. `typ` is
`mission-approval-context-v1`; `value` is the object above with no
conditional member added.

~~~ text
{"iss":"https://as.example.com","typ":"mission-approval-context-v1",
"value":{"approval_basis":{"activation":{"approval_event_id":"ape_8K
2nP4qV9rL3tY6sB1z"},"activation_actor":{"iss":"https://idp.example.c
om","sub":"user_3p2q8mN1a0kV7tR"},"adjudication":{"kind":"human"},"c
onsent_principal":{"iss":"https://idp.example.com","sub":"user_3p2q8
mN1a0kV7tR"},"root_commitment":"sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1
cF8gH2vJ4kE5pNQ","type":"direct"},"approval_event_id":"ape_8K2nP4qV9
rL3tY6sB1z","approver":{"iss":"https://idp.example.com","sub":"user_
3p2q8mN1a0kV7tR"},"authority_hash":"sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM
7sX1cF8gH2vJ4kE5pNQ","authority_source":{"type":"user_delegated"},"c
lient_id":"s6BhdRkqt3","created_at":"2026-10-15T14:32:11Z","expires_
at":"2026-12-31T23:59:59Z","id":"msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9
-","intent_hash":"sha-256:wQ7p4LHnX9Md0LqJ6sZJ8b8mZ3rN2xT5pV4lE6sQqY
Y","issuer":"https://as.example.com","policy_version":"deploy-policy
:v17","subject":{"iss":"https://idp.example.com","sub":"user_3p2q8mN
1a0kV7tR"}}}
~~~

~~~ text
approval_context_commitment = sha-256:iRCrkxJWsQL1ZlXYQg1FUy2OIBKFpF
n99tYA-2qlC48
~~~

**Vector 2: conditional `proposal_hash`.** This is the canonical
Mission unchanged: the always-present members above plus
`"proposal_hash": "sha-256:kT2mR7vX4qL9nY5pB1sD8fJ6wZ3hC0aGeUoNvSqMrYo"`.

~~~ text
{"iss":"https://as.example.com","typ":"mission-approval-context-v1",
"value":{"approval_basis":{"activation":{"approval_event_id":"ape_8K
2nP4qV9rL3tY6sB1z"},"activation_actor":{"iss":"https://idp.example.c
om","sub":"user_3p2q8mN1a0kV7tR"},"adjudication":{"kind":"human"},"c
onsent_principal":{"iss":"https://idp.example.com","sub":"user_3p2q8
mN1a0kV7tR"},"root_commitment":"sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1
cF8gH2vJ4kE5pNQ","type":"direct"},"approval_event_id":"ape_8K2nP4qV9
rL3tY6sB1z","approver":{"iss":"https://idp.example.com","sub":"user_
3p2q8mN1a0kV7tR"},"authority_hash":"sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM
7sX1cF8gH2vJ4kE5pNQ","authority_source":{"type":"user_delegated"},"c
lient_id":"s6BhdRkqt3","created_at":"2026-10-15T14:32:11Z","expires_
at":"2026-12-31T23:59:59Z","id":"msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9
-","intent_hash":"sha-256:wQ7p4LHnX9Md0LqJ6sZJ8b8mZ3rN2xT5pV4lE6sQqY
Y","issuer":"https://as.example.com","policy_version":"deploy-policy
:v17","proposal_hash":"sha-256:kT2mR7vX4qL9nY5pB1sD8fJ6wZ3hC0aGeUoNv
SqMrYo","subject":{"iss":"https://idp.example.com","sub":"user_3p2q8
mN1a0kV7tR"}}}
~~~

~~~ text
approval_context_commitment = sha-256:7ikugIQZvSkie-Pc25V_sJKGHU5HGy
mVfrnMaIc8So0
~~~

**Vector 3: conditional `ceiling_hash`.** Diverges from the canonical
Mission by adding a Progressive ceiling and carrying no
`proposal_hash` (isolating the `ceiling_hash` case). `ceiling_hash`
is derived first, per the Progressive profile's own construction
({{I-D.draft-mcguinness-oauth-mission-progressive}}): `typ`
`mission-authority-ceiling`, `value` a two-member object of
`authority_ceiling` and `drawdown_policy`.

~~~ json
{
  "authority_ceiling": [
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["invoices.read", "invoices.write"] }
  ],
  "drawdown_policy": "https://as.example.com/policies/erp-drawdown-v1"
}
~~~

~~~ text
{"iss":"https://as.example.com","typ":"mission-authority-ceiling","v
alue":{"authority_ceiling":[{"actions":["invoices.read","invoices.wr
ite"],"resource":"https://erp.example.com","type":"mission_resource_
access"}],"drawdown_policy":"https://as.example.com/policies/erp-dra
wdown-v1"}}
~~~

~~~ text
ceiling_hash = sha-256:IcftaaatF3MgmbbcDoXB6hEi-kqy-y2IFD2PCeZfB_Q
~~~

The manifest is the always-present members above plus this
`ceiling_hash`:

~~~ text
{"iss":"https://as.example.com","typ":"mission-approval-context-v1",
"value":{"approval_basis":{"activation":{"approval_event_id":"ape_8K
2nP4qV9rL3tY6sB1z"},"activation_actor":{"iss":"https://idp.example.c
om","sub":"user_3p2q8mN1a0kV7tR"},"adjudication":{"kind":"human"},"c
onsent_principal":{"iss":"https://idp.example.com","sub":"user_3p2q8
mN1a0kV7tR"},"root_commitment":"sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1
cF8gH2vJ4kE5pNQ","type":"direct"},"approval_event_id":"ape_8K2nP4qV9
rL3tY6sB1z","approver":{"iss":"https://idp.example.com","sub":"user_
3p2q8mN1a0kV7tR"},"authority_hash":"sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM
7sX1cF8gH2vJ4kE5pNQ","authority_source":{"type":"user_delegated"},"c
eiling_hash":"sha-256:IcftaaatF3MgmbbcDoXB6hEi-kqy-y2IFD2PCeZfB_Q","
client_id":"s6BhdRkqt3","created_at":"2026-10-15T14:32:11Z","expires
_at":"2026-12-31T23:59:59Z","id":"msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc
9-","intent_hash":"sha-256:wQ7p4LHnX9Md0LqJ6sZJ8b8mZ3rN2xT5pV4lE6sQq
YY","issuer":"https://as.example.com","policy_version":"deploy-polic
y:v17","subject":{"iss":"https://idp.example.com","sub":"user_3p2q8m
N1a0kV7tR"}}}
~~~

~~~ text
approval_context_commitment = sha-256:aj_DeEf0vbk7jZnXOMEFiFVSmD0SQg
5MEXIMUXSWLFs
~~~

**Vector 4: conditional `submission_evidence_commitment`.** Diverges
from the canonical Mission by recording one verified Intent Submission
Evidence entry and carrying no `proposal_hash` (isolating the
`submission_evidence_commitment` case). `artifact_hash` is derived
first, over the entry exactly as presented
({{I-D.draft-mcguinness-oauth-mission}}): `typ`
`mission-intent-evidence`.

~~~ json
{
  "type": "mission-intent-admission-assertion",
  "assertion": "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FkbWlzc2lvbi5leGFtcGxlLmNvbSJ9.MEUCIQDx7vector"
}
~~~

~~~ text
{"iss":"https://as.example.com","typ":"mission-intent-evidence","val
ue":{"assertion":"eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FkbWlzc
2lvbi5leGFtcGxlLmNvbSJ9.MEUCIQDx7vector","type":"mission-intent-admi
ssion-assertion"}}
~~~

~~~ text
artifact_hash = sha-256:EwtVufH4c6btTaI55w-3mDJaNg0miFuC6-T7jXU2-R8
~~~

The recorded `submission_evidence` array carries this one element;
`submission_evidence_commitment` is a second envelope anchor, `typ`
`mission-submission-evidence-v1`, `value` the array exactly as
retained:

~~~ json
[
  { "type": "mission-intent-admission-assertion",
    "artifact_hash":
      "sha-256:EwtVufH4c6btTaI55w-3mDJaNg0miFuC6-T7jXU2-R8",
    "verified_at": "2026-10-15T14:31:50Z",
    "facts": {
      "admission_issuer": "https://admission.example.com",
      "status": "active"
    } }
]
~~~

~~~ text
{"iss":"https://as.example.com","typ":"mission-submission-evidence-v
1","value":[{"artifact_hash":"sha-256:EwtVufH4c6btTaI55w-3mDJaNg0miF
uC6-T7jXU2-R8","facts":{"admission_issuer":"https://admission.exampl
e.com","status":"active"},"type":"mission-intent-admission-assertion
","verified_at":"2026-10-15T14:31:50Z"}]}
~~~

~~~ text
submission_evidence_commitment = sha-256:TwDmwzJgsm8Ik86YuybyctIaMPZ
K-aKeU6a2BF0kTi0
~~~

The manifest is the always-present members above plus this
`submission_evidence_commitment`:

~~~ text
{"iss":"https://as.example.com","typ":"mission-approval-context-v1",
"value":{"approval_basis":{"activation":{"approval_event_id":"ape_8K
2nP4qV9rL3tY6sB1z"},"activation_actor":{"iss":"https://idp.example.c
om","sub":"user_3p2q8mN1a0kV7tR"},"adjudication":{"kind":"human"},"c
onsent_principal":{"iss":"https://idp.example.com","sub":"user_3p2q8
mN1a0kV7tR"},"root_commitment":"sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1
cF8gH2vJ4kE5pNQ","type":"direct"},"approval_event_id":"ape_8K2nP4qV9
rL3tY6sB1z","approver":{"iss":"https://idp.example.com","sub":"user_
3p2q8mN1a0kV7tR"},"authority_hash":"sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM
7sX1cF8gH2vJ4kE5pNQ","authority_source":{"type":"user_delegated"},"c
lient_id":"s6BhdRkqt3","created_at":"2026-10-15T14:32:11Z","expires_
at":"2026-12-31T23:59:59Z","id":"msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9
-","intent_hash":"sha-256:wQ7p4LHnX9Md0LqJ6sZJ8b8mZ3rN2xT5pV4lE6sQqY
Y","issuer":"https://as.example.com","policy_version":"deploy-policy
:v17","subject":{"iss":"https://idp.example.com","sub":"user_3p2q8mN
1a0kV7tR"},"submission_evidence_commitment":"sha-256:TwDmwzJgsm8Ik86
YuybyctIaMPZK-aKeU6a2BF0kTi0"}}
~~~

~~~ text
approval_context_commitment = sha-256:Msha2eEDtfucgANzT5nmO90gtCEXFQ
FdRfVUGmOwCZE
~~~

**Vector 5: mutated-member rejection.** Vector 2's manifest with one
member changed, `approval_event_id` from `ape_8K2nP4qV9rL3tY6sB1z` to
`ape_9K2nP4qV9rL3tY6sB1z`, illustrating what {{approval-context-computation}}
requires a verifier to do when a recomputed digest disagrees with a
disclosed one:

~~~ text
recomputed = sha-256:3ZcZC8vR2HiCkgZqop_fUBaAwmj6hLknF8ey9g44dD8
disclosed  = sha-256:7ikugIQZvSkie-Pc25V_sJKGHU5HGymVfrnMaIc8So0
~~~

The two differ, so a verifier holding the mutated record and this
disclosed vector-2 value MUST reject the reference.

**Vector 6: wrong-`typ` rejection.** Vector 2's `value` object,
unchanged, committed under `typ` `mission-approval-context-v2`
instead of `mission-approval-context-v1`:

~~~ text
correct typ (v1) = sha-256:7ikugIQZvSkie-Pc25V_sJKGHU5HGymVfrnMaIc8S
o0
wrong typ (v2)   = sha-256:KSLVjgQRCWLHsswYmBJS2B_n0SPRAZjTvBnkIRqw-
aw
~~~

The two differ. A verifier's recompute is always fixed to
`mission-approval-context-v1`; presented with the wrong-`typ` value
as if it were vector 2's `approval_context_commitment`, it recomputes
vector 2's correct digest, finds a mismatch, and rejects under the
same rule as vector 5.

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

{{policy-approval-recency}} bounds the AGR `policy` assertion path
and, by extension, a standing-consent Mission whose `approval_basis`
record stands in for that assertion ({{assertion-requirements}}). The
issuance profile's standing-consent authority bases carry their own
human-approval instant, in `approval_basis.approved_at`, traced
through `consent_principal` and a commitment
({{I-D.draft-mcguinness-oauth-mission}}); the template profile's
`template` basis and the progressive profile's `ceiling_drawdown`
basis both populate it, and each profile declares its own maximum age
against it: `review_cadence` for template, the ceiling review cadence
for progressive
({{I-D.draft-mcguinness-oauth-mission-template}},
{{I-D.draft-mcguinness-oauth-mission-progressive}}).

The two recency paths are therefore analogous, each bounding staleness
against a retained human-approval instant, but distinct in what they
gate: this section's ceiling governs whether the issuer may count a
`policy` assertion, or activate a Mission whose `approval_basis`
stands in for one, at evaluation; a profile's own maximum age governs
whether the dispatch or drawdown may happen at all, independent of
whether an AGR is ever recorded.

A standing-consent Mission's accountable-approver rule is satisfied by
`approval_basis` itself ({{assertion-requirements}}), never by
fabricating a `policy` assertion in its place; the high-risk-class
default of this section still binds that record directly.

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

## Stale Policy Approval

Without {{policy-approval-recency}}, a `policy` assertion could rely
on a human approval far in the past, or stand in for the accountable
approver on a high-risk consequence with no human assertion at all.
The recency ceiling, its ordering checks, and the human-by-default
consequence-class rule are the control.

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

IANA is requested to register two media types per {{RFC6838}}: the
Approval Governance Record object, and the JWS-secured representation
its `envelope` carries (using the `+jws` structured syntax suffix
already registered with IANA).

### application/mission-approval-governance+jws

- Type name: application
- Subtype name: mission-approval-governance+jws
- Required parameters: none
- Optional parameters: none
- Encoding considerations: binary; a JWS Compact Serialization:
  base64url-encoded values separated by period characters. The
  secured payload's media type travels in the JWS protected `cty`
  ({{envelope}}).
- Security considerations: see {{security-considerations}}
- Interoperability considerations: see this document ({{envelope}})
- Published specification: this document
- Applications that use this media type: Mission-Bound Authorization
  approval governance
- Fragment identifier considerations: N/A
- Additional information:
  - Deprecated alias names for this type: none
  - Magic number(s): none
  - File extension(s): none
  - Macintosh file type code(s): N/A
- Person & email address to contact for further information:
  Karl McGuinness <public@karlmcguinness.com>
- Intended usage: COMMON
- Restrictions on usage: none
- Author: IETF
- Change controller: IETF

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
- enforce the strictest applicable policy-approval maximum age across
  the consequence classes the committed Mission's derived Authority
  Set and Mission Intent carry, from a committed ceiling
  and any committed exception ({{policy-approval-recency}});
- require `kind: human` for the accountable-approver assertion where
  the committed Mission's derived Authority Set or Mission Intent
  carries a high-risk class, unless a committed
  class-named exception applies ({{policy-approval-recency}});
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
