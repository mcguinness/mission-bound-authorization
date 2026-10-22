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
  RFC8792:
  RFC9396:
  I-D.draft-mcguinness-oauth-mission-progressive:
    title: "Mission Progressive Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-progressive.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
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

Mission-Bound Authorization records one accountable Approver for each
Mission and leaves multi-party approval and approval-authority
provenance to a governance layer. This document defines that layer's
record, the Approval Governance Record: an issuer-signed,
issuer-retained record of the policy, assertions, and evaluation behind
one approval event. Before the Mission is created, the record is part of
the approval decision; afterwards, it is immutable evidence of who
approved, under which authority, and why the decision satisfied
governance. The record never appears on tokens or protocol messages, and
the Mission's single accountable Approver is unchanged.

This document also defines the `governed_policy` approval basis, under
which a policy version that an accountable human approved activates
Mission proposals, and the Approval Context Commitment, a digest over a
Mission's immutable creation facts that lets two authenticated artifacts
be matched to one approval.

--- middle

# Introduction {#introduction}

Mission-Bound Authorization records one accountable Approver for each
Mission and leaves multi-party approval and approval-authority
provenance to a governance layer. Mission-Bound Authorization for OAuth
2.0 {{I-D.draft-mcguinness-oauth-mission}} (the "issuance profile")
states this rule for the OAuth binding, which records the Approver in
`approval_basis.consent_principal`; this document consumes that
binding's record members.

An enterprise review process is often that governance layer. One
approval can involve several principals, a threshold or
separation-of-duty rule, and a delegation-of-authority policy. An
auditor later has to prove not only who approved, but under which
authority the approval was valid.

The issuance profile answers who is accountable for a Mission. This
document answers under which authority that approval was made, and why
it satisfied governance. It defines:

- the Approval Governance Record (AGR), the record of the policy,
  assertions, and evaluation behind one approval event ({{record}});
- the `governed_policy` approval basis ({{governed-policy}}), under
  which an accountable human approves a bounded policy version once, and
  that policy then decides eligible Mission proposals, each activation
  committing a record; and
- the Approval Context Commitment ({{approval-context-commitment}}), an
  optional digest over a Mission's immutable creation facts that other
  authenticated artifacts can disclose.

The record has two phases:

- Before commitment, it is part of the approval decision. An assertion
  that fails authentication, event binding, or policy authorization does
  not contribute ({{assertion-requirements}}), and a record that cannot
  be evaluated or persisted prevents activation ({{atomic-commitment}}).
- After commitment, it is evidence: immutable, signed ({{envelope}}),
  and consumed by audit, never by enforcement.

This document is optional. A deployment that records nothing beyond the
Mission Record's accountable `approval_basis.consent_principal` is fully
conformant to its Mission binding and unaffected by this document. A
profile can require the record; {{triggers}} defines the conditions
under which one does.

The record is independent of the approval ceremony. It applies alike to
synchronous approval, to deferred approval
({{I-D.draft-mcguinness-oauth-mission-approval}}), and to the native
asynchronous approval of a standalone Mission Authority Server
({{I-D.draft-mcguinness-mission-authority-server}}), and it depends on
no deferral substrate.

# Conventions and Definitions {#conventions-and-definitions}

{::boilerplate bcp14-tagged}

All JSON shown in this document is non-normative and illustrative; the
member definitions in the surrounding text are authoritative. An example
line too long for the page is folded with the single backslash strategy
of {{RFC8792}}; the canonical-bytes blocks of
{{approval-context-vectors}} are wrapped as that appendix describes.

This document uses JSON {{RFC8259}} as the data model for the Approval
Governance Record. JCS canonicalization {{RFC8785}} applies wherever
this document computes a digest or a signing input, under the
canonicalization rules of {{I-D.draft-mcguinness-oauth-mission}}; this
document does not define a second canonicalization.

A digest is encoded in the integrity-anchor encoded form of
{{I-D.draft-mcguinness-oauth-mission}}: the `sha-256:` prefix followed
by the base64url, no-padding encoding of the digest. This document
defines no digest algorithm of its own. Its digests are constructed with
the issuance profile's commitment mechanisms
({{I-D.draft-mcguinness-oauth-mission}}) and classified under the
substrate's default commitment construction, which this document imports
normatively ({{I-D.draft-mcguinness-mission-substrate}}):
`approval_policy.digest`, `approval_context_commitment`, and
`submission_evidence_commitment` are envelope anchors, and the record
digest ({{envelope}}) is a canonical-object digest.

The terms Mission, Mission Record, Mission Issuer, Approver, Subject,
approval event, Mission Intent, Authority Set, audit horizon,
`approval_event_id`, `intent_hash`, and `authority_hash` are used as
defined in {{I-D.draft-mcguinness-oauth-mission}}.

This document defines the following terms:

Approval Governance Record (AGR):
: The policy, assertions, and evaluation standing behind one approval
  event ({{record}}).

Assertion:
: One principal's authenticated decision statement carried in an AGR
  ({{assertion-members}}).

Accountable assertion:
: The assertion that satisfies the accountable-approver rule
  ({{accountable-assertion}}).

Evaluation:
: The issuer's determination of whether the recorded assertions satisfy
  the referenced approval policy ({{atomic-commitment}}).

Record digest:
: The digest over a complete record, `envelope` included, that every
  external binding names ({{envelope}}).

Recording trigger:
: A condition under which a profile requires this record for an approval
  event ({{triggers}}).

Recording Issuer:
: A Mission Issuer that records Approval Governance Records
  ({{conformance}}).

Relying Auditor:
: A party that verifies a retained record and can re-check its
  evaluation ({{conformance}}).

# Relationship to the Issuance Profile {#issuance-relationship}

The Mission Record carries exactly one accountable principal,
`approval_basis.consent_principal`, and this document does not change
that. The accountable Approver remains the only principal that any
downstream projection, token, or enforcement point consumes. The record
captures the standing behind that approval, never a second authorization
surface visible outside the issuer.

The `approval_event_id` member joins the record to the approval event
and to the Mission Record it governs
({{I-D.draft-mcguinness-oauth-mission}}). The record never appears on
tokens or in any protocol message; it is issuer-retained control-plane
state. OAuth standardizes the authorization data that a client requests
and is granted ({{RFC9396}} for rich authorization requests), not an
organization's internal approval provenance, so the record also stays
out of enforcement projections, matching the issuance profile's
control-plane discipline.

The record governs the Mission approval event. An action-time approval
under the runtime profile's re-evaluation surfaces
({{I-D.draft-mcguinness-mission-runtime}}) is a different layer and
never joins this record.

Where the governed Mission populates `approval_basis.adjudication`
({{I-D.draft-mcguinness-oauth-mission}}, Section "Role Mapping") and
this record exists:

- `adjudication.governance_record` is `true`;
- `adjudication.kind` names the mechanism the approval basis fixes:
  `human` for `direct`, and `policy` for a standing-consent basis,
  including `governed_policy` ({{governed-policy}}). It is never a value
  that names this record itself, and never a flattening of its assertion
  set into a single principal; and
- where the record carries an accountable assertion
  ({{assertion-requirements}}), that assertion's own `kind` MUST equal
  `adjudication.kind`.

# Recording Triggers {#triggers}

A profile MAY require this record; the Enterprise Mission Authority
Profile does so under these recording triggers
({{I-D.draft-mcguinness-mission-authority-server}}). The triggers are
defined here so that a profile cites one list. Under a profile that
adopts these recording triggers, the record is REQUIRED for an approval
event when any of the following holds:

1. the Mission Record's `approval_basis.consent_principal` differs
   from its `subject`;
2. more than one principal contributes to the decision;
3. a non-human assertion contributes to the decision;
4. a threshold, veto, or separation-of-duty rule is evaluated; or
5. validating any assertion requires authority standing outside the
   Mission Record.

A deployment that adopts no profile requiring the record has no
obligation to record one merely because a trigger holds. Independently
of any profile, every activation under `governed_policy` records an
Approval Governance Record ({{governed-policy}}). Every Approval
Governance Record a deployment records, whether required or not, MUST
satisfy the requirements of this document.

The Approver is always `approval_basis.consent_principal`
({{I-D.draft-mcguinness-oauth-mission}}), so a Mission whose Approver
differs from its Subject holds the first trigger, and the Enterprise
Mission Authority Profile always records an Approval Governance Record
for it.

Direct self-approval by one authenticated human is the degenerate case:
the Mission Record already carries it completely, and no record is
required. This presumes that the human resolved the approval on the
approval surface itself. Where an agent resolves it on its own behalf,
there is no human decision for this list to be degenerate about
({{I-D.draft-mcguinness-mission-runtime}}).

The following table gives an example approval for each trigger, and for
the degenerate case. Each row names one trigger that holds; others can
hold too.

| Approval | Trigger that holds |
|---|---|
| A manager approves a Mission whose Subject is Alice | The Approver differs from the Subject |
| Alice and a finance co-approver both approve | More than one principal contributes |
| A delegation-of-authority policy asserts alongside Alice ({{record-example}}) | A non-human assertion contributes |
| A two-of-three finance rule decides the approval | A threshold rule is evaluated |
| An approver's authority comes from a delegation matrix held outside the Mission Record | Validating an assertion requires outside standing |
| Alice alone approves her own Mission on the approval surface | None; no record is required |
{: title="Recording trigger examples"}

# The Approval Governance Record {#record}

An Approval Governance Record is a JSON object. {{record-members}},
{{assertion-members}} and {{assertion-authority}} define its members.
{{assertion-requirements}} and {{atomic-commitment}} define how the
issuer builds and commits it, and {{envelope}} defines its integrity
protection.

## Record Members {#record-members}

`approval_event_id`:
: REQUIRED. A string. The approval event's identifier, equal to the
  Mission Record's `approval_event_id`
  ({{I-D.draft-mcguinness-oauth-mission}}).

`mission`:
: REQUIRED. An object binding the record to the approved Mission:
  `issuer` (the Mission Issuer), `intent_hash`, and `authority_hash`,
  each equal to the committed Mission Record member of the same name. A
  record whose binding does not match the Mission Record it is retained
  with is invalid.

`approval_policy`:
: REQUIRED. An object identifying the governing delegation-of-authority
  policy: `id` (an identifier), `version` (a string), and `digest` (an
  integrity anchor over the retained policy snapshot, in the encoded
  form {{conventions-and-definitions}} fixes). {{approval-policy}}
  defines the digest and the snapshot's retention.

`assertions`:
: REQUIRED. An array of one or more decision assertions
  ({{assertion-members}}).

`evaluation`:
: REQUIRED. An object recording the outcome, with these members:

    `decision`:
    : REQUIRED. A string. The only value a committed record carries is
      `approved`, since a record exists only for an approval that
      committed ({{atomic-commitment}}).

    `evaluated_at`:
    : REQUIRED. An RFC 3339 timestamp.

    `contributing`:
    : REQUIRED. An array of the `assertion_id` values the evaluation
      counted toward the rule the approval satisfied. A denial the
      policy evaluated that did not block the approval is recorded but
      not contributing, and a blocking denial leaves no committed record
      ({{atomic-commitment}}), so a `deny` assertion never appears in
      `contributing`.

`approval_context_commitment`:
: OPTIONAL. A string. The Approval Context Commitment over the governed
  Mission's immutable creation facts ({{approval-context-commitment}}),
  in the encoded form {{conventions-and-definitions}} fixes. It is a
  member of this record, never of the Mission Record
  ({{approval-context-computation}}). An issuer that records it computes
  it in the same commit that creates the Mission and persists this
  record, before the record is signed ({{atomic-commitment}}), so the
  signed payload commits to it. A verifier checks it against the Mission
  Record ({{envelope}}).

`envelope`:
: REQUIRED. An object. Integrity protection over the members above, in
  the form {{envelope}} defines.

## Assertion Members {#assertion-members}

Each element of `assertions` is an object with these members:

`assertion_id`:
: REQUIRED. A string, unique within the record.

`principal`:
: REQUIRED. An object with `iss` and `sub`: the principal in whose name
  the assertion is made.

  - For a `human` assertion, the authenticated human who decided.
  - For a `policy` assertion, the human who approved the exact policy
    version its `authority` names (where a consented root commits a
    separate evaluator that decides, the human who approved that root),
    as the issuer's retained, authenticated governance state records.
    Where several humans approved that version together, as under dual
    control, it is the one human that state names as accountable for the
    approval, as the issuance profile records one accountable Approver
    ({{I-D.draft-mcguinness-oauth-mission}}, Section "Single Accountable
    Approver"). The policy is the decision mechanism, never the
    principal.
  - For a `service` assertion, the service that produced the decision.

`kind`:
: REQUIRED. A string, one of `human`, `service`, or `policy`.

`decision`:
: REQUIRED. A string, one of `approve` or `deny`.

`decided_at`:
: REQUIRED. An RFC 3339 {{RFC3339}} timestamp.

`authority`:
: REQUIRED. An object recording the provenance under which the principal
  was authorized to decide. Its members depend on `kind`
  ({{assertion-authority}}).

`reason`:
: OPTIONAL. A string.

## Assertion Authority {#assertion-authority}

An assertion's `authority` is an object whose members depend on the
assertion's `kind`. Each member below states its type, its presence, and
the source the issuer takes it from. A member this section does not
define for the assertion's `kind` carries no semantics under this
document.

A `human` assertion's `authority` records the authentication the issuer
verified for the decision ({{assertion-validation}}):

`auth_time`:
: REQUIRED. An RFC 3339 timestamp: when the principal authenticated for
  this decision.

`acr`:
: A string: the authentication context class reference of that
  authentication. REQUIRED when the issuer possesses it at the approval
  event.

`amr`:
: An array of strings: the authentication methods references of that
  authentication. REQUIRED when the issuer possesses them at the
  approval event.

The issuer takes these members from the authentication it verified,
never from the requesting client or agent.

A `policy` assertion's `authority` names the deciding policy version and
its human approval:

`policy_id`:
: REQUIRED. A string: the identifier of the policy that decided.

`version`:
: REQUIRED. A string: the exact version of that policy.

`approved_at`:
: REQUIRED. An RFC 3339 timestamp: the human approval instant of that
  exact policy version, not the assertion instant. The `decided_at`
  member records when the policy asserted, and `approved_at` records
  when a human approved the version it asserts under.

`approved_by`:
: OPTIONAL. An object with `iss` and `sub`: the human who approved that
  version. When present, it MUST equal `principal`.

The issuer takes `policy_id` and `version` from the policy it evaluated,
or from the authenticated decision it verified. The `approved_at` and
`approved_by` members are corroborated provenance, never
self-authenticating evidence: the issuer MUST verify `approved_at` from
retained, authenticated governance state for the named `policy_id` and
`version`, and it MUST NOT accept `approved_at` as the assertion's own
uncorroborated clock value ({{policy-approval-recency}}). It takes
`approved_by` from the same state and MUST NOT accept it from the
asserting party.

A `service` assertion's `authority` identifies the logic that produced
the decision, and the model where a model produced it:

`logic_id`:
: REQUIRED. A string: the identifier of the logic (for example, a
  workflow, a rule engine, or a model) that produced the decision.

`logic_version`:
: REQUIRED. A string: the version of that logic.

`model_id`:
: A string: the identifier of the model that produced the decision.
  REQUIRED where a model produced it.

`model_version`:
: A string: the version of that model. REQUIRED where `model_id` is
  present.

Where the logic is itself a model, `logic_id` and `logic_version` carry
the model's identifier and version, as `model_id` and `model_version`
do. The issuer takes these members from the integrity-protected channel
or signature it verified for the assertion ({{assertion-validation}}).

## Approval Policy Reference {#approval-policy}

The `approval_policy.digest` preimage is the issuance profile's
integrity-anchor envelope ({{I-D.draft-mcguinness-oauth-mission}}),
canonicalized with JCS {{RFC8785}}, with these members:

- `typ`: `mission-approval-policy`, which domain-separates this anchor
  from every other integrity anchor;
- `iss`: the Mission Issuer, which prevents cross-issuer replay; and
- `value`: an object of `content_type` (the snapshot's media type) and
  `content` (the base64url, no-padding encoding of the snapshot bytes).

The snapshot bytes and their media type, or the referenced policy
version they represent, MUST be retained for the Mission's audit horizon
({{I-D.draft-mcguinness-oauth-mission}}), so an independent auditor
reproduces the digest exactly and re-checks the evaluation against the
policy that governed it.

Threshold, quorum, veto, and separation-of-duty semantics live in the
referenced policy; any human-readable summary of them in deployment
tooling is advisory and carries no semantics in this record.

## Example {#record-example}

The following is an example of an Approval Governance Record. Its
Mission, `msn_h8ucQfVYsc9ttvVWaQ2SN6ZKc5KLpUlj`, is not the issuance
profile's Worked Example Mission, but it shares that Mission's Intent
and Authority Set, and so its anchors.

~~~ json
{
  "approval_event_id": "ape_hON9D0svLKQAMyy-uug",
  "mission": {
    "issuer": "https://as.example.com",
    "intent_hash":
      "sha-256:6T-7s_f-mNW9UpfrrZh3r0HRJmU4My_EsNAf1C1U4r0",
    "authority_hash":
      "sha-256:hjXlwWBY64-RPs1Z-E_gbyklNcViI5c9jiyMbE4KvFM"
  },
  "approval_policy": {
    "id": "dlg-matrix",
    "version": "v7",
    "digest":
      "sha-256:OAbEIh2DTYUVP7DjRhHct4aapsT8PybZq2ILdut9UP0"
  },
  "assertions": [
    { "assertion_id": "ast_1",
      "principal": { "iss": "https://idp.example.com",
        "sub": "user_3p2q8mN1a0kV7tR" },
      "kind": "human", "decision": "approve",
      "decided_at": "2026-11-02T08:00:00Z",
      "authority": { "acr": "urn:example:acr:phishing-resistant",
        "amr": ["pwd", "hwk"],
        "auth_time": "2026-11-02T07:59:00Z" } },
    { "assertion_id": "ast_2",
      "principal": { "iss": "https://idp.example.com",
        "sub": "user_dC9yqLHPbadQRVw" },
      "kind": "policy", "decision": "approve",
      "decided_at": "2026-11-02T08:00:00Z",
      "authority": { "policy_id": "dlg-matrix", "version": "v7",
        "approved_at": "2026-09-15T09:00:00Z" } }
  ],
  "evaluation": {
    "decision": "approved",
    "evaluated_at": "2026-11-02T08:00:00Z",
    "contributing": ["ast_1", "ast_2"]
  },
  "envelope": {
    "format": "jws-compact",
    "value": "eyJhbGciOiJFUzI1NiIsImtpZCI6ImFzLWtleS0y..."
  }
}
~~~

In this example:

- The Mission Record's accountable `approval_basis.consent_principal` is
  Alice (`user_3p2q8mN1a0kV7tR` at `https://idp.example.com`). `ast_1`
  is her own `approve` assertion, which satisfies the
  accountable-approver rule of {{accountable-assertion}} directly.
- `ast_2` is a `policy` assertion in the name of the human who approved
  `dlg-matrix` version `v7` (`user_dC9yqLHPbadQRVw`). It is recorded
  alongside the accountable assertion rather than in place of it.
  Because a second principal and a non-human assertion contribute, the
  second and third recording triggers hold ({{triggers}}).
- The `envelope` member's `value` is the JWS whose payload is the JCS
  canonical bytes of this object with `envelope` itself removed
  ({{envelope}}).

# Assertion Requirements {#assertion-requirements}

These rules govern the assertions the issuer evaluates
({{atomic-commitment}}).

## Assertion Validation {#assertion-validation}

The following rules apply to the assertions in a record:

- Every assertion that contributes to the evaluation MUST be
  authenticated: a `human` assertion with the authentication the
  issuance profile requires of an Approver at an approval event, a
  `service` or `policy` assertion through an integrity-protected channel
  or signature the issuer verifies.
- Every assertion MUST be bound to this approval event: an assertion is
  made against this `approval_event_id`, this `intent_hash`, and this
  `authority_hash`, and an assertion captured for one event MUST NOT be
  replayed into another. An assertion that can narrow the authority,
  such as a model output an activation consults, is made against the
  `authority_hash` of the set it evaluated rather than of the narrowed
  result; the issuer records that set with the activation's inputs, and
  the committed Authority Set lies within it.
- Every contributing assertion MUST be policy-authorized: before
  counting it, the issuer verifies that the asserting principal was
  eligible to assert under the referenced `approval_policy` version. For
  a `policy` assertion, that means both that the policy its `authority`
  names was eligible to decide under `approval_policy` and that its
  principal was eligible to approve that policy version (or, where a
  consented root commits a separate evaluator that decides, that root).
- Denials and vetoes MUST be recorded: an assertion set that omits a
  negative assertion misrepresents the decision.

An assertion that fails authentication, event binding, or policy
authorization MUST NOT contribute to the evaluation and MUST NOT be
counted toward any policy rule.

The following example shows the `assertions` and `evaluation` members of
a record, other members omitted, whose delegation-of-authority policy
requires one finance approval beside the accountable approver's. Alice
approves directly; one finance approver approves and another denies.
Under that policy a finance denial does not block an approval that
another finance approver supports, so the denial is recorded but not
contributing.

~~~ json
{
  "assertions": [
    { "assertion_id": "ast_1",
      "principal": { "iss": "https://idp.example.com",
        "sub": "user_3p2q8mN1a0kV7tR" },
      "kind": "human", "decision": "approve",
      "decided_at": "2026-11-02T08:00:00Z",
      "authority": {
        "acr": "urn:example:acr:phishing-resistant",
        "amr": ["pwd", "hwk"],
        "auth_time": "2026-11-02T07:59:00Z" } },
    { "assertion_id": "ast_2",
      "principal": { "iss": "https://idp.example.com",
        "sub": "user_t1yd3CZCLPOis5n" },
      "kind": "human", "decision": "approve",
      "decided_at": "2026-11-02T07:58:10Z",
      "authority": {
        "acr": "urn:example:acr:phishing-resistant",
        "amr": ["pwd", "hwk"],
        "auth_time": "2026-11-02T07:58:00Z" } },
    { "assertion_id": "ast_3",
      "principal": { "iss": "https://idp.example.com",
        "sub": "user_Kq-iUUKDYl8jhWF" },
      "kind": "human", "decision": "deny",
      "decided_at": "2026-11-02T07:57:40Z",
      "authority": {
        "acr": "urn:example:acr:phishing-resistant",
        "amr": ["pwd", "hwk"],
        "auth_time": "2026-11-02T07:57:30Z" },
      "reason": "Asks for a lower journal-entry cap." }
  ],
  "evaluation": {
    "decision": "approved",
    "evaluated_at": "2026-11-02T08:00:00Z",
    "contributing": ["ast_1", "ast_2"]
  }
}
~~~

More than one principal contributes and a threshold rule is evaluated,
so the second and fourth recording triggers hold ({{triggers}}).

## Accountable Assertion {#accountable-assertion}

The accountable-approver rule ties a record to the Mission's one
accountable principal, the Mission Record's
`approval_basis.consent_principal`. The Mission's `approval_basis.type`
fixes how a record satisfies it:

- For `direct`, the record MUST carry exactly one `human` assertion
  whose `principal` is `consent_principal` and whose `decision` is
  `approve`: the human decision a `direct` approval event carries
  ({{I-D.draft-mcguinness-oauth-mission}}). Contributing `policy` and
  `service` assertions do not replace it.
- For `governed_policy`, the record MUST carry exactly one `policy`
  assertion whose `principal` is `consent_principal`, whose `decision`
  is `approve`, and whose `authority` names the deciding policy
  ({{governed-policy-record}}). The policy is the decision mechanism,
  and the principal stays the human who approved it.
- For any other named standing-consent `approval_basis`
  ({{I-D.draft-mcguinness-oauth-mission}}), the Mission satisfies the
  rule through its authenticated `approval_basis` record, not through an
  assertion: `consent_principal`, `root_commitment`, and `approved_at`,
  fixed at the approval event and immutable, stand in for an accountable
  assertion. The record can still carry contributing `policy` and
  `service` assertions.

A record that does not satisfy the rule for its basis does not commit
({{atomic-commitment}}). The assertion that satisfies it under `direct`
or `governed_policy` is the accountable assertion; no other basis has
one. The accountable assertion's `kind` MUST be `human` or `policy`: a
`service` assertion, including one a model produced, is a contributing
governance input, never the accountable assertion. Under every basis,
the high-risk-class restrictions of {{recency-high-risk}} apply.

No assertion is fabricated in the name of the activating policy or the
requesting actor to stand in for a fresh human decision that did not
occur.

Where the Mission populates `approval_basis.adjudication`, the
accountable assertion's `kind` also equals `adjudication.kind`
({{issuance-relationship}}).

# Policy-Approval Recency {#policy-approval-recency}

This section bounds staleness on the AGR `policy` assertion path: it
governs a `policy` assertion's `authority.approved_at` and the `kind` of
the accountable assertion ({{accountable-assertion}}). It does not apply
to a `human` assertion, whose `decided_at` is the approval instant
itself.

## Recency Declarations {#recency-declarations}

A Recording Issuer that admits `policy` assertions MUST declare a
maximum policy-approval age per consequence class (a **recency
ceiling**) and a bounded clock-skew allowance, and MAY declare, per
class, an **exception** admitting a `policy` assertion as the
accountable assertion for that class, each exception carrying its own
maximum age.

The ceiling, the skew allowance, and any exception MUST be part of the
retained `approval_policy` snapshot that `approval_policy.digest`
commits ({{approval-policy}}), or a separately versioned declaration
committed from that snapshot. A mutable, out-of-band deployment
statement MUST NOT serve this role: it would make the evaluation
impossible to reproduce, contrary to the purpose of the retained policy,
which lets an auditor re-run the decision ({{approval-policy}}).

## Evaluating Recency {#recency-evaluation}

At evaluation, the issuer MUST classify the committed Mission's
consequence classes from the derived Authority Set and from any
consumption bound the Mission Intent carries
({{I-D.draft-mcguinness-mission-metering}}). The issuer MUST select,
across every class either source carries, the strictest maximum age that
applies, accounting for any declared exception. This is a property of
the whole committed Mission the record's `mission.authority_hash` and
`mission.intent_hash` bind to ({{record-members}}), never of one
assertion or entry in isolation. For a class with a declared exception,
the maximum that applies is the smaller of that class's recency ceiling
and the exception's maximum age: an exception admits a `policy`
accountable assertion for its class and never lengthens the ceiling.

For each `policy` assertion the evaluation would count toward the
applicable maximum, the issuer:

- uses the `authority.approved_at` it verified under
  {{assertion-authority}};
- MUST measure the assertion's age as `evaluation.evaluated_at` minus
  `authority.approved_at`, using the atomic-commitment instant
  ({{atomic-commitment}});
- MUST enforce `authority.approved_at` <= `decided_at` <=
  `evaluation.evaluated_at`, subject to the declared clock-skew
  allowance; and
- MUST reject the assertion if `authority.approved_at` or `decided_at`
  is later than the issuer's own clock at evaluation, beyond that
  allowance.

A `policy` assertion whose age exceeds the applicable maximum, or whose
ordering the checks above do not admit, fails policy-authorization under
{{assertion-validation}}: the issuer MUST NOT count it toward the
evaluation, and by {{atomic-commitment}} the Mission MUST NOT be created
`active` on an evaluation that depended on it.

An `evaluation.evaluated_at` later than the issuer's own clock, beyond
the declared allowance, is a defect of the record rather than of one
assertion: the evaluation MUST NOT be treated as complete, and by
{{atomic-commitment}} the Mission MUST NOT be created `active` on it.

## High-Risk Classes {#recency-high-risk}

Four conditions are the high-risk classes the issuance profile defines:
irreversible action, external commitment, privileged administration, and
a consumption bound ({{I-D.draft-mcguinness-oauth-mission}}). Where the
committed Mission's derived Authority Set or Mission Intent
({{I-D.draft-mcguinness-mission-metering}}) carries one, the assertion
satisfying the accountable-approver rule of {{accountable-assertion}}
MUST be `kind: human`, unless a committed, class-named exception under
{{recency-declarations}} admits `kind: policy` for that class.

Only `governed_policy` has a `policy` accountable assertion
({{accountable-assertion}}), so a governed policy activates a Mission
carrying one of these classes only under such an exception.

The same default binds a Mission whose accountable-approver rule is
satisfied through its own `approval_basis` record rather than an
assertion ({{accountable-assertion}}): recording an AGR for such a
Mission carrying one of the four classes requires a committed,
class-named exception under {{recency-declarations}}; absent it, the
record MUST NOT be created and, by {{atomic-commitment}}, the Mission
MUST NOT be created `active`.

## Scope of the Recency Rules {#recency-scope}

Recency is issuance-time eligibility. It determines whether a Mission
activates and does not reach back into a Mission already `active`: that
Mission's governing policy approval was measured fresh at its own
approval event, and a later change to the ceiling, the exception, or the
policy's freshness does not narrow or terminate it.

Approval Governance is an optional extension ({{introduction}}). The
rules of {{policy-approval-recency}} are a conservative default of this
document, not a guarantee of every Mission-Bound Authorization
deployment, and a deployment that records no Approval Governance Record
is unbounded by them.

The `kind: human` requirement is not by itself an assurance property:
the authentication-strength, rendering, and accountable-principal
requirements the issuance profile and {{assertion-requirements}}
otherwise impose still carry that property; {{policy-approval-recency}}
only decides which assertion kind MUST be present.

## Relationship to Standing-Consent Recency {#recency-standing-consent}

{{policy-approval-recency}} bounds the AGR `policy` assertion path and,
by extension, a standing-consent Mission whose `approval_basis` record
stands in for that assertion ({{accountable-assertion}}).

The issuance profile's standing-consent bases carry their own
human-approval instant in `approval_basis.approved_at`, traced through
`consent_principal` and a commitment
({{I-D.draft-mcguinness-oauth-mission}}). The template profile's
`template` basis and the progressive profile's `ceiling_drawdown` basis
both populate it, and each profile declares its own maximum age against
it: `review_cadence` for template, and the ceiling review cadence for
progressive ({{I-D.draft-mcguinness-oauth-mission-template}},
{{I-D.draft-mcguinness-oauth-mission-progressive}}).

Under `governed_policy` the two instants coincide:
`approval_basis.approved_at` equals the accountable `policy` assertion's
`authority.approved_at` ({{governed-policy-record}}). This document's
ceiling therefore bounds that basis, alongside any standing-consent
recency ceiling the deployment declares
({{I-D.draft-mcguinness-oauth-mission}}, Section "Standing-Consent
Recency").

The two recency paths are analogous, each bounding staleness against a
retained human-approval instant, but they gate different things:

- this document's ceiling governs whether the issuer may count a
  `policy` assertion, or activate a Mission whose `approval_basis`
  stands in for one, at evaluation; and
- a profile's own maximum age governs whether the dispatch or drawdown
  may happen at all, independent of whether an AGR is ever recorded.

# Evaluation and Atomic Commitment {#atomic-commitment}

Where a deployment records the Approval Governance Record for an
approval, the record and the Mission are one commit. Within that commit,
the issuer:

- validates the assertions ({{assertion-requirements}});
- evaluates them under the referenced policy version;
- where the record carries `approval_context_commitment`
  ({{record-members}}), computes it from the Mission Record being
  created;
- signs the evaluated record ({{envelope}}); and
- persists the signed record in the same commit as the Mission's
  creation.

The only order the commit fixes is evaluate, then sign, then persist,
with `approval_context_commitment` computed before signing; the other
checks this document requires, including those of
{{governed-policy-activation}}, complete before signing, in whatever
order their inputs allow. A value of `approval_context_commitment`
computed after the commit is not covered by the record's signature and
MUST NOT be added to a committed record.

Where a deployment records the Approval Governance Record for an
approval, the Mission Record MUST NOT be created `active` unless the
evaluation's `decision` is `approved` and the signed record persists
atomically with the Mission's creation. Failure to authenticate the
contributing assertions, to complete the evaluation, or to persist the
record MUST prevent activation; there is no Mission whose governance
record was meant to exist and does not.

A governance evaluation that denies creates no Mission and no committed
record. Negative assertions retained inside a committed record document
dissent ({{assertion-validation}}), and a wholly declined approval's
evidence surface is consent evidence's declined outcome
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}), which exists
without a Mission Record.

A committed record is immutable. A subsequent governance action, such as
a re-review or an incident finding, is a new record about a new event,
never an edit.

# Envelope and Verification {#envelope}

The `envelope` member ({{record-members}}) is an object with `format` (a
string, required) and `value` (a string, required). The default `format`
is `jws-compact`: a JWS Compact Serialization {{RFC7515}} over the JCS
{{RFC8785}} canonical bytes of the record with the `envelope` member
removed, signed by the Mission Issuer under a key resolvable in its
published key material. The signed record, `envelope` included, is the
retained, registrable form.

This document defines only the `jws-compact` format; an implementation
MUST reject an envelope whose `format` is unsupported rather than
accepting it unverified.

The JWS protected header MUST carry:

- a `kid` resolvable in the Mission Issuer's published key material;
- a `typ` of `mission-approval-governance+jws`; and
- a `cty` of `mission-approval-governance+json`.

These values are the registered media types
`application/mission-approval-governance+jws` and
`application/mission-approval-governance+json` ({{iana}}) with the
`application/` prefix omitted, as Sections 4.1.9 and 4.1.10 of
{{RFC7515}} recommend.

A verifier compares each value as a media type under those sections: it
treats a value that contains no `/` as if `application/` were prepended,
and it compares type and subtype names case-insensitively. Neither media
type defines a parameter, so a value that carries one matches neither. A
verifier MUST accept either form of each value, and MUST reject a JWS
whose protected header lacks `typ` or `cty`, or whose `typ` or `cty`
does not match this pair. Normalization applies only to the comparison:
a verifier MUST NOT rewrite the signed header, the payload, or the
retained record, so the record digest below covers the record exactly as
signed and retained.

The following is the decoded JWS protected header of the `envelope`
value in {{record-example}}:

~~~ json
{
  "alg": "ES256",
  "kid": "as-key-2",
  "typ": "mission-approval-governance+jws",
  "cty": "mission-approval-governance+json"
}
~~~

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
5. Validate the mission binding of {{record-members}} against the
   Mission Record it is retained with.

Where the record carries `approval_context_commitment`, the `mission`
member carries no Mission `id`, so a verifier recomputes the commitment
from the Mission Record this record is retained with, which step 5
resolves, and rejects the reference on a mismatch
({{approval-context-computation}}).

The **record digest** is the digest, in the encoded form
{{conventions-and-definitions}} fixes, over the JCS {{RFC8785}}
canonical bytes of the complete record, `envelope` included. It is the
one byte sequence every external reference names:

- audit registration hashes exactly these bytes ({{audit-evidence}});
  and
- consent evidence's `approval_governance_digest` equals exactly this
  value ({{consent-evidence-relationship}}).

# Re-checking an Evaluation {#re-check}

A Relying Auditor re-checks an evaluation by replaying it from retained
evidence: the policy and any evaluator that decided, the inputs they
evaluated, and the recorded assertions. Conformance requires it to
obtain the retained policy version before treating the evaluation as
re-checked ({{conformance}}). The re-check has these steps:

1. Verify the record ({{envelope}}).
2. Obtain the retained snapshot of the `approval_policy` version the
   record names, and recompute `approval_policy.digest` over it
   ({{approval-policy}}).
3. Where that snapshot commits a separate evaluator that decides, as a
   `governed_policy` root can ({{governed-policy-root}}), obtain the
   retained snapshot of that evaluator and recompute its activation
   policy reference digest ({{I-D.draft-mcguinness-oauth-mission}},
   Section "Activation Policy Commitment").
4. Obtain the inputs the deciding policy or evaluator evaluated, as the
   issuer recorded them ({{I-D.draft-mcguinness-oauth-mission}}, Section
   "Principals and Approval Basis"). These include each model output in
   full, with its verdict and any narrowing, which the matching
   `service` assertion records only by identifier. Confirm that each
   input carries this record's `approval_event_id`, the Mission's
   `intent_hash`, and the `authority_hash` of the set recorded as
   evaluated, and that each contributing `service` assertion corresponds
   to one of them.
5. Re-run the deciding policy or evaluator, at its exact version, over
   those inputs and the recorded assertions, and confirm that it
   approves, counting exactly the assertions `contributing` lists
   ({{record-members}}).
6. Apply the recency rules of {{policy-approval-recency}}, as the
   snapshot or the declaration it commits states them, with
   `evaluation.evaluated_at` as the evaluation instant.

Where a snapshot, the evaluator, or an input cannot be obtained, a
recomputed digest does not match, a binding does not hold, or the replay
reaches a different outcome, the evaluation is not re-checked.

A re-check does not re-authenticate an assertion: the record carries an
assertion's authentication context ({{assertion-authority}}), not the
authentication itself.

# Governed Policy Approval {#governed-policy}

This document defines the `governed_policy` standing-consent basis on
the issuance profile's extension point for named standing-consent
bases ({{I-D.draft-mcguinness-oauth-mission}}, Section
"Standing-Consent Bases"). An accountable human approves a bounded
policy version once; that policy then activates eligible Mission
proposals with no fresh human decision per instance. Every activation
under this basis MUST record an Approval Governance Record, committed
with the Mission ({{atomic-commitment}}).

## Consented Root {#governed-policy-root}

The consented root is the retained `approval_policy` snapshot that a
human approved ({{approval-policy}}). It commits:

- the clients, Subjects, and authority sources that can activate
  under it;
- the authority ceiling and the lifetime limits of each activated
  Mission;
- the deterministic rules that decide an activation;
- the recency ceilings, the clock-skew allowance, and any class-named
  exceptions of {{policy-approval-recency}}; and
- where a separate policy artifact decides instances, that artifact's
  activation policy reference ({{I-D.draft-mcguinness-oauth-mission}},
  Section "Activation Policy Commitment").

The root decides whether an instance activates. It is distinct from
an `organizational` authority source's `authority_source.policy`,
which bounds whose authority the Mission draws on
({{I-D.draft-mcguinness-oauth-mission}}).

The issuer MUST establish the standing consent, the consenting human,
and that human's approval of the exact root version from retained,
authenticated governance state, never from the activating request: a
submitted proposal cannot supply its own standing consent.

The root and a separate evaluator keep distinct digest domains:
`approval_policy.digest` commits the root under `typ`
`mission-approval-policy` ({{approval-policy}}), and the activation
policy reference commits the evaluator under `typ`
`mission-activation-policy`. The issuer MUST NOT accept either digest in
place of the other.

## Instance Record {#governed-policy-record}

A Mission activated under this basis records these `approval_basis`
members ({{I-D.draft-mcguinness-oauth-mission}}), each REQUIRED:

`type`:
: `governed_policy`.

`consent_principal`:
: The human who approved the exact root version.

`approved_at`:
: The instant of that approval, verified against retained,
  authenticated state as the issuance profile requires of every
  standing-consent basis.

`root_commitment`:
: The root's `approval_policy.digest`; the record's own
  `approval_policy` is that root.

`activation`:
: An object of `approval_event_id`, equal to the Mission's own
  `approval_event_id`, and `policy`, an object of the deciding
  policy's `id`, `version`, and `digest`.

`activation_actor`:
: The authenticated client that requested this activation, distinct
  from `consent_principal`.

`adjudication`:
: `kind` `policy`, with `policy` naming the deciding policy's `id`
  and `version`, and `governance_record` `true`.

The deciding policy is the root itself or the separate evaluator the
root commits, never another policy. Its digest in `activation.policy`
is `approval_policy.digest` when the root decides, and the
evaluator's `mission-activation-policy` digest when the evaluator
decides.

The instance's `approval_event_id` identifies this activation's approval
event, never the human's approval of the root. The issuer allocates one
per proposal it activates, so a retried or concurrent activation of the
same proposal resolves to one Mission and one record, and each distinct
activation creates its own Mission.

The record's accountable assertion ({{assertion-requirements}}) MUST
be a `policy` assertion whose `principal` is `consent_principal` and
whose `authority` names the deciding policy's `id` and `version` with
`approved_at` equal to `approval_basis.approved_at`. Like every
contributing assertion, it is authenticated and bound to this
approval event. It records the policy's decision under that human's
standing authorization, not a fresh human action.

## Activation {#governed-policy-activation}

At the atomic creation commit ({{atomic-commitment}}), the issuer
MUST, before it creates the Mission `active`:

1. Resolve the standing consent from retained, authenticated state
   and confirm that it still admits new activations.
2. Verify that the consenting human was authorized to approve the
   exact root version and approved it at `approved_at`, and recompute
   `approval_policy.digest` over the retained snapshot.
3. Where the root commits a separate evaluator, recompute that
   evaluator's digest over the exact snapshot evaluated
   ({{I-D.draft-mcguinness-oauth-mission}}, Section
   "Activation Policy Commitment").
4. Establish the Subject and the authority source as the issuance
   profile requires, and verify that the requesting client, the
   Subject, and the source are ones the root admits.
5. Derive the Authority Set under the issuance profile's derivation
   and authority-proposal rules, within the source's ceiling and the
   root's authority ceiling, and bound the effective expiry by the
   Mission Intent and the root's lifetime limits.
6. Evaluate the deciding policy, at its exact version, over recorded
   inputs.
7. Apply the policy-approval recency rules
   ({{policy-approval-recency}}) across the whole derived Mission,
   including any consumption bound, so a high-risk class activates
   only under a committed, class-named exception.
8. Bind every assertion and the record to this instance's
   `approval_event_id`, `intent_hash`, and `authority_hash`
   ({{assertion-validation}}, {{record-members}}), except that a model
   output binds to the `authority_hash` of the set it evaluated.
9. Sign the record and commit it with the `active` Mission
   ({{atomic-commitment}}).

A failure at any step creates no Mission and issues no credential.

A model's output enters only as a recorded input at step 6: it can
refuse an activation or narrow the authority activated, and never
supplies authority or decides the approval
({{I-D.draft-mcguinness-oauth-mission}}, Section "Principals and
Approval Basis").

Withdrawing the standing consent stops every later activation under
it (step 1). A Mission already activated keeps its ordinary
lifecycle: withdrawal does not revoke it.

## Example {#governed-policy-example}

The following example shows an excerpt, other members omitted, of the
Mission Record of `msn_UDgovqrOTIZyJgTEp0DjopwF2gRseSfT`, activated
under `governed_policy`. Alice approved the policy `q3-close-agent`
version 3 at 2026-10-30T16:00:00Z. The client `s6BhdRkqt3` later
proposed the issuance profile's Worked Example task, and the policy
activated it at 2026-11-02T08:00:00Z with no fresh human decision. The
Mission shares the Worked Example Mission's Intent and Authority Set,
and so its anchors. The policy digest stands for a policy snapshot this
example does not display.

~~~ json
{
  "id": "msn_UDgovqrOTIZyJgTEp0DjopwF2gRseSfT",
  "issuer": "https://as.example.com",
  "subject": { "iss": "https://idp.example.com",
    "sub": "user_3p2q8mN1a0kV7tR" },
  "approval_basis": {
    "type": "governed_policy",
    "consent_principal": { "iss": "https://idp.example.com",
      "sub": "user_3p2q8mN1a0kV7tR" },
    "approved_at": "2026-10-30T16:00:00Z",
    "root_commitment":
      "sha-256:nw0FRGuMWUqNMS9BwKpEpqcvZwwO9DGrrujtlMNTAJU",
    "activation": {
      "approval_event_id": "ape_7d2sUfnZmgimG0bc67hu",
      "policy": { "id": "q3-close-agent", "version": "3",
        "digest":
          "sha-256:nw0FRGuMWUqNMS9BwKpEpqcvZwwO9DGrrujtlMNTAJU" } },
    "activation_actor": { "iss": "https://as.example.com",
      "sub": "s6BhdRkqt3" },
    "adjudication": { "kind": "policy",
      "policy": { "id": "q3-close-agent", "version": "3" },
      "governance_record": true }
  },
  "authority_source": { "type": "user_delegated" },
  "client_id": "s6BhdRkqt3",
  "approval_event_id": "ape_7d2sUfnZmgimG0bc67hu",
  "created_at": "2026-11-02T08:00:00Z"
}
~~~

The following is an example of the Approval Governance Record committed
with that Mission:

~~~ json
{
  "approval_event_id": "ape_7d2sUfnZmgimG0bc67hu",
  "mission": {
    "issuer": "https://as.example.com",
    "intent_hash":
      "sha-256:6T-7s_f-mNW9UpfrrZh3r0HRJmU4My_EsNAf1C1U4r0",
    "authority_hash":
      "sha-256:hjXlwWBY64-RPs1Z-E_gbyklNcViI5c9jiyMbE4KvFM"
  },
  "approval_policy": {
    "id": "q3-close-agent",
    "version": "3",
    "digest":
      "sha-256:nw0FRGuMWUqNMS9BwKpEpqcvZwwO9DGrrujtlMNTAJU"
  },
  "assertions": [
    { "assertion_id": "ast_1",
      "principal": { "iss": "https://idp.example.com",
        "sub": "user_3p2q8mN1a0kV7tR" },
      "kind": "policy", "decision": "approve",
      "decided_at": "2026-11-02T08:00:00Z",
      "authority": { "policy_id": "q3-close-agent", "version": "3",
        "approved_at": "2026-10-30T16:00:00Z" } }
  ],
  "evaluation": {
    "decision": "approved",
    "evaluated_at": "2026-11-02T08:00:00Z",
    "contributing": ["ast_1"]
  },
  "envelope": {
    "format": "jws-compact",
    "value": "eyJhbGciOiJFUzI1NiIsImtpZCI6ImFzLWtleS0y..."
  }
}
~~~

In this example:

- The root decides activations itself, with no separate evaluator, so
  `root_commitment`, `activation.policy.digest`, and
  `approval_policy.digest` carry one value ({{governed-policy-record}}).
- The client `s6BhdRkqt3` requested the activation. It is the
  `activation_actor`, distinct from the `consent_principal`, Alice.
- `ast_1` is the accountable assertion: a `policy` assertion whose
  `principal` is Alice and whose `approved_at` equals
  `approval_basis.approved_at` ({{governed-policy-record}}). Because a
  non-human assertion contributes, the third recording trigger also
  holds ({{triggers}}).
- The root declares a 30-day recency ceiling for every consequence
  class, a 60-second clock-skew allowance, and an exception that admits
  a `policy` accountable assertion for irreversible actions, with a
  maximum age of 7 days ({{recency-declarations}}). The issuer
  classifies `journal-entries.write` as an irreversible action and finds
  no other high-risk class, so the exception applies and the strictest
  applicable maximum is 7 days ({{recency-evaluation}}).
- At `evaluated_at`, `ast_1` is 2 days and 16 hours old, and
  `approved_at` <= `decided_at` <= `evaluated_at` holds, so the issuer
  counts it. Without the exception, the accountable assertion would have
  to be `kind: human`, and the policy could not activate this Mission
  ({{recency-high-risk}}).

# Consent Evidence Relationship {#consent-evidence-relationship}

Where both are recorded, the AGR is authoritative for
approval-governance facts, and consent evidence presents a
deliberately partial view of it
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}). Agreement
is testable, member by member:

- Each `co_approvals` entry MUST correspond to exactly one `human`
  assertion in the record with the same `principal`, the entry's
  decision equal to the assertion's `decision`, and the entry's
  timestamp equal to the assertion's `decided_at`. Omitting an assertion
  is permitted; an entry with no corresponding assertion, or one that
  alters a decision or time, is an integrity failure. Assertions of kind
  `service` or `policy` are governance inputs, never consent events, and
  are never presented as co-approvals.
- The consent evidence `approver` MUST equal the `principal` of the
  record's accountable assertion ({{accountable-assertion}}); for a
  standing-consent Mission whose accountable-approver rule is
  satisfied by `approval_basis` rather than an assertion, it MUST
  equal `approval_basis.consent_principal` instead.
- `approval_authority`, when present, MUST equal
  `approval_policy.id`; `approval_policy_version`, when present,
  MUST equal `approval_policy.version`.
- `approval_governance_digest`, when present, MUST equal the record
  digest ({{envelope}}).

The AGR governs on any disagreement.

The following example shows the members of a Consent Evidence object
that correspond to the record in {{record-example}}, other members
omitted:

~~~ json
{
  "approver": { "iss": "https://idp.example.com",
    "sub": "user_3p2q8mN1a0kV7tR" },
  "approval_authority": "dlg-matrix",
  "approval_policy_version": "v7",
  "approval_governance_digest":
    "sha-256:j6eaQoHcHpH-fntRE1DkZgCDjBZZLxXrCwpHfTWCWnQ"
}
~~~

The `approver` member is the principal of the accountable assertion,
`ast_1`. There is no `co_approvals` member: the record's only other
assertion, `ast_2`, is a `policy` assertion, which is never presented as
a co-approval. The `approval_governance_digest` value stands for the
record digest of the complete record, whose `envelope` value that
example abbreviates.

Where a deferred approval revises under Mission Approval Revision
({{I-D.draft-mcguinness-oauth-mission-approval-revision}}) and the
deployment records consent evidence, each `revision_required` outcome
produces a `narrowed` consent-evidence decision with no corresponding
record: no Mission yet exists for the atomic commitment rule
({{atomic-commitment}}) to attach to. This is a deliberate artifact
separation, not an authority conflict:

- where consent evidence is recorded, it owns the narrowing history,
  through its `narrowed` entries and `predecessor_intent_hashes`; and
- where an AGR is recorded for the final approval, it owns the final
  approval-governance facts.

# Mission Evidence {#audit-evidence}

The AGR is registrable Mission evidence under the audit transparency
profile's evidence-type pattern
({{I-D.draft-mcguinness-mission-audit}}), with:

- canonical bytes: the JCS canonical bytes of the complete record,
  `envelope` included, which are the record-digest preimage
  ({{envelope}});
- `payload-preimage-content-type`:
  `application/mission-approval-governance+json`; and
- authoritative producer: the Mission `issuer`.

Registration is optional transparency hardening; retention and
immutability do not depend on it.

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
({{I-D.draft-mcguinness-oauth-mission}}). Each member copies the Mission
Record member of the same name, verbatim, except:

- `approver` copies the Mission Record's
  `approval_basis.consent_principal`; and
- `submission_evidence_commitment` is computed from the Mission Record's
  `submission_evidence` ({{approval-context-construction}}).

A conditional member is present if and only if its condition holds:

| Member | Presence |
|---|---|
| `issuer` | always |
| `id` | always |
| `intent_hash` | always |
| `proposal_hash` | when the Mission Record carries `proposal_hash` |
| `authority_hash` | always |
| `ceiling_hash` | when the Mission Record carries `ceiling_hash` |
| `subject` | always |
| `approver` | always |
| `client_id` | always |
| `created_at` | always |
| `expires_at` | always |
| `approval_basis` | always |
| `authority_source` | always |
| `policy_version` | always |
| `approval_event_id` | always |
| `submission_evidence_commitment` | when the Mission Record carries `submission_evidence` |
{: title="Approval Context Manifest v1 members"}

The presence of every conditional member MUST be a deterministic
function of the Mission Record alone, never of which companion
profiles a deployment runs: two parties holding the same record
compute the same manifest.

The `ceiling_hash` member is the manifest's fourth anchor alongside
`intent_hash`, `proposal_hash`, and `authority_hash`: the manifest MUST
include `ceiling_hash` when the Mission Record carries one and MUST omit
it when the Mission Record carries none. The manifest copies the
recorded value verbatim, as it copies every other member, so computing
or verifying the manifest never computes `ceiling_hash`. Its
construction and semantics belong to the Progressive profile
({{I-D.draft-mcguinness-oauth-mission-progressive}}), and adopting this
Approval Context Commitment profile does not require adopting
Progressive.

The manifest excludes the Mission Record's mutable members, `state`
and `termination`, and every value that is not itself a member of the
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
Record holds it. A deployment MAY cache the computed
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

# Conformance {#conformance}

A Recording Issuer MUST:

- authenticate, event-bind, and policy-authorize every contributing
  assertion ({{assertion-validation}});
- record denials ({{assertion-validation}});
- satisfy the accountable-approver rule for the Mission's approval
  basis: exactly one matching `human` assertion under `direct`, exactly
  one matching `policy` assertion under `governed_policy`, and the
  authenticated `approval_basis` under any other standing-consent basis
  ({{accountable-assertion}});
- evaluate under the retained policy version ({{atomic-commitment}});
- enforce the strictest applicable policy-approval maximum age across
  the consequence classes the committed Mission's derived Authority
  Set and Mission Intent carry, from a committed ceiling
  and any committed exception ({{policy-approval-recency}});
- where the committed Mission's derived Authority Set or Mission Intent
  carries a high-risk class, require a `human` accountable assertion
  unless a committed class-named exception applies, and require such an
  exception for a basis without an accountable assertion
  ({{recency-high-risk}});
- under `governed_policy`, record the members of
  {{governed-policy-record}} and complete the activation checks of
  {{governed-policy-activation}};
- commit the record atomically with Mission creation and let failure
  prevent activation ({{atomic-commitment}});
- sign the evaluated record before it is committed, and keep the
  committed record immutable ({{atomic-commitment}}, {{envelope}}); and
- retain the record and the referenced policy for the Mission's
  audit horizon ({{I-D.draft-mcguinness-oauth-mission}}).

A Relying Auditor MUST verify the envelope by byte equality, MUST
validate the mission binding, and MUST obtain the retained policy
version before treating the evaluation as re-checked ({{envelope}},
{{approval-policy}}, {{re-check}}).

# Security Considerations {#security-considerations}

The security considerations of the issuance profile
({{I-D.draft-mcguinness-oauth-mission}}) apply. The following
considerations are specific to the Approval Governance Record.

## Forged or Padded Assertions

A forged or padded assertion is an authorization attack before
commitment, not an audit defect: the assertion requirements of
{{assertion-requirements}} are the control, and a deployment that
records assertions without authenticating them has built an approval
bypass rather than an evidence trail.

## Policy Substitution

Without `approval_policy.digest` and its retention, a later reading
cannot prove which policy governed the evaluation. The digest and
the audit-horizon retention of {{approval-policy}} are the control.

## Manufactured Accountability

The accountable-approver rule of {{accountable-assertion}} prevents a
set of service and policy assertions from claiming a Mission whose named
Approver never asserted anything. Because that assertion is never
`service`, a model-backed service cannot become the accountable
approver: no human-approved policy stands behind its decision, so it
contributes only as a governance input.

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

The Approval Context Commitment extends this to the Mission Record's
creation facts, approval basis included. A verifier that recomputes it
and gets a value different from the one an artifact discloses rejects
that artifact's reference ({{approval-context-computation}}). A
mismatch shows only that the artifact and the current record disagree.
The artifact's signature authenticates the value it discloses, not
when it was made, since the issuer can backdate a signed artifact.
Where an audit receipt ({{audit-evidence}}) independently shows that
the artifact existed before the record changed, and the disclosed
value matches a recomputation from the approval event as registered,
the mismatch is evidence that the record was altered afterwards.

## Issuer Key Compromise

This document inherits the issuance profile's key-material
considerations. A compromised Mission Issuer signing key can mint a
plausible record; audit registration
({{I-D.draft-mcguinness-mission-audit}}) is the existence bound, not
a substitute for key custody.

# Privacy Considerations {#privacy-considerations}

The privacy considerations of the issuance profile
({{I-D.draft-mcguinness-oauth-mission}}) apply. Assertion principals and
decision times are personal data about reviewers. The record is
control-plane state retained by the issuer, never disclosed on wire
surfaces, and access to a retained record follows the issuer's audit-log
discipline for approval-event records
({{I-D.draft-mcguinness-oauth-mission}}). The
`approval_context_commitment` value is the same in every artifact that
discloses it, so it correlates those artifacts
({{approval-context-carriage}}). A `service` assertion's `authority`
discloses the identifiers and versions of the logic and model that took
part in a decision ({{assertion-authority}}).

# IANA Considerations {#iana}

## Media Type Registration

IANA is requested to register two media types per {{RFC6838}}:

- `application/mission-approval-governance+jws`, the JWS-secured
  representation that a record's `envelope` carries, using the `+jws`
  structured syntax suffix; and
- `application/mission-approval-governance+json`, the Approval
  Governance Record object.

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

--- back

# Approval Context Commitment Test Vectors {#approval-context-vectors}

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
state its divergence.

Vectors 1, 3, and 4 are hypothetical variants
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
    "sha-256:6T-7s_f-mNW9UpfrrZh3r0HRJmU4My_EsNAf1C1U4r0",
  "authority_hash":
    "sha-256:hjXlwWBY64-RPs1Z-E_gbyklNcViI5c9jiyMbE4KvFM",
  "subject": { "iss": "https://idp.example.com",
    "sub": "user_3p2q8mN1a0kV7tR" },
  "approver": { "iss": "https://idp.example.com",
    "sub": "user_3p2q8mN1a0kV7tR" },
  "client_id": "s6BhdRkqt3",
  "created_at": "2026-11-02T08:00:00Z",
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
      "sha-256:hjXlwWBY64-RPs1Z-E_gbyklNcViI5c9jiyMbE4KvFM"
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
mN1a0kV7tR"},"root_commitment":"sha-256:hjXlwWBY64-RPs1Z-E_gbyklNcVi
I5c9jiyMbE4KvFM","type":"direct"},"approval_event_id":"ape_8K2nP4qV9
rL3tY6sB1z","approver":{"iss":"https://idp.example.com","sub":"user_
3p2q8mN1a0kV7tR"},"authority_hash":"sha-256:hjXlwWBY64-RPs1Z-E_gbykl
NcViI5c9jiyMbE4KvFM","authority_source":{"type":"user_delegated"},"c
lient_id":"s6BhdRkqt3","created_at":"2026-11-02T08:00:00Z","expires_
at":"2026-12-31T23:59:59Z","id":"msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9
-","intent_hash":"sha-256:6T-7s_f-mNW9UpfrrZh3r0HRJmU4My_EsNAf1C1U4r
0","issuer":"https://as.example.com","policy_version":"deploy-policy
:v17","subject":{"iss":"https://idp.example.com","sub":"user_3p2q8mN
1a0kV7tR"}}}
~~~

~~~ text
approval_context_commitment = sha-256:dPaMl8eUhPExoiVA2zHbz4wPzmDLVs
fZnHDxCYHDGos
~~~

**Vector 2: conditional `proposal_hash`.** This is the canonical Mission
unchanged: the always-present members above plus
`"proposal_hash": "sha-256:p-s-EzdNQTn6RoPHXESkwVtGdk8yL1PxryNyMwroKGo"`.

~~~ text
{"iss":"https://as.example.com","typ":"mission-approval-context-v1",
"value":{"approval_basis":{"activation":{"approval_event_id":"ape_8K
2nP4qV9rL3tY6sB1z"},"activation_actor":{"iss":"https://idp.example.c
om","sub":"user_3p2q8mN1a0kV7tR"},"adjudication":{"kind":"human"},"c
onsent_principal":{"iss":"https://idp.example.com","sub":"user_3p2q8
mN1a0kV7tR"},"root_commitment":"sha-256:hjXlwWBY64-RPs1Z-E_gbyklNcVi
I5c9jiyMbE4KvFM","type":"direct"},"approval_event_id":"ape_8K2nP4qV9
rL3tY6sB1z","approver":{"iss":"https://idp.example.com","sub":"user_
3p2q8mN1a0kV7tR"},"authority_hash":"sha-256:hjXlwWBY64-RPs1Z-E_gbykl
NcViI5c9jiyMbE4KvFM","authority_source":{"type":"user_delegated"},"c
lient_id":"s6BhdRkqt3","created_at":"2026-11-02T08:00:00Z","expires_
at":"2026-12-31T23:59:59Z","id":"msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9
-","intent_hash":"sha-256:6T-7s_f-mNW9UpfrrZh3r0HRJmU4My_EsNAf1C1U4r
0","issuer":"https://as.example.com","policy_version":"deploy-policy
:v17","proposal_hash":"sha-256:p-s-EzdNQTn6RoPHXESkwVtGdk8yL1PxryNyM
wroKGo","subject":{"iss":"https://idp.example.com","sub":"user_3p2q8
mN1a0kV7tR"}}}
~~~

~~~ text
approval_context_commitment = sha-256:pGxfIDuyBPfgpyox3J6GP477CQfUE6
FS9CfHirjwwvU
~~~

**Vector 3: conditional `ceiling_hash`.** Diverges from the canonical
Mission by adding a Progressive ceiling and carrying no `proposal_hash`
(isolating the `ceiling_hash` case). The `ceiling_hash` value is derived
first, per the Progressive profile's own construction
({{I-D.draft-mcguinness-oauth-mission-progressive}}): `typ`
`mission-authority-ceiling`, `value` a two-member object of
`authority_ceiling` and `drawdown_policy`. The ceiling covers the
Authority Set, its read entry's delegation grant included, with the
write actions in a separate entry that grants no delegation, and
`drawdown_policy` is an activation policy reference whose `digest`
stands for a policy snapshot this example does not display.

~~~ json
{
  "authority_ceiling": [
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["invoices.read"],
      "delegation": {
        "max_depth": 2,
        "allowed_delegates": [{ "sub_profile": "ai_agent" }]
      } },
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["invoices.write", "journal-entries.write"] }
  ],
  "drawdown_policy": {
    "id": "erp-drawdown",
    "version": "1",
    "digest":
      "sha-256:_hLEAl_ir1vxnex2tgbS6eRR99lyL1r6yyeB4RrC184"
  }
}
~~~

~~~ text
{"iss":"https://as.example.com","typ":"mission-authority-ceiling","v
alue":{"authority_ceiling":[{"actions":["invoices.read"],"delegation
":{"allowed_delegates":[{"sub_profile":"ai_agent"}],"max_depth":2},"
resource":"https://erp.example.com","type":"mission_resource_access"
},{"actions":["invoices.write","journal-entries.write"],"resource":"
https://erp.example.com","type":"mission_resource_access"}],"drawdow
n_policy":{"digest":"sha-256:_hLEAl_ir1vxnex2tgbS6eRR99lyL1r6yyeB4Rr
C184","id":"erp-drawdown","version":"1"}}}
~~~

~~~ text
ceiling_hash = sha-256:I0TgJBsdSkkmaHt4EayPfIjs8uoYiuQvP_O5b9Tlec8
~~~

The manifest is the always-present members above plus this
`ceiling_hash`:

~~~ text
{"iss":"https://as.example.com","typ":"mission-approval-context-v1",
"value":{"approval_basis":{"activation":{"approval_event_id":"ape_8K
2nP4qV9rL3tY6sB1z"},"activation_actor":{"iss":"https://idp.example.c
om","sub":"user_3p2q8mN1a0kV7tR"},"adjudication":{"kind":"human"},"c
onsent_principal":{"iss":"https://idp.example.com","sub":"user_3p2q8
mN1a0kV7tR"},"root_commitment":"sha-256:hjXlwWBY64-RPs1Z-E_gbyklNcVi
I5c9jiyMbE4KvFM","type":"direct"},"approval_event_id":"ape_8K2nP4qV9
rL3tY6sB1z","approver":{"iss":"https://idp.example.com","sub":"user_
3p2q8mN1a0kV7tR"},"authority_hash":"sha-256:hjXlwWBY64-RPs1Z-E_gbykl
NcViI5c9jiyMbE4KvFM","authority_source":{"type":"user_delegated"},"c
eiling_hash":"sha-256:I0TgJBsdSkkmaHt4EayPfIjs8uoYiuQvP_O5b9Tlec8","
client_id":"s6BhdRkqt3","created_at":"2026-11-02T08:00:00Z","expires
_at":"2026-12-31T23:59:59Z","id":"msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc
9-","intent_hash":"sha-256:6T-7s_f-mNW9UpfrrZh3r0HRJmU4My_EsNAf1C1U4
r0","issuer":"https://as.example.com","policy_version":"deploy-polic
y:v17","subject":{"iss":"https://idp.example.com","sub":"user_3p2q8m
N1a0kV7tR"}}}
~~~

~~~ text
approval_context_commitment = sha-256:85y0i-t8pwRsM-SwHgZ9EaBIQFbnWj
YDjBNEO1TTQWA
~~~

**Vector 4: conditional `submission_evidence_commitment`.** Diverges
from the canonical Mission by recording one verified Intent Submission
Evidence entry and carrying no `proposal_hash` (isolating the
`submission_evidence_commitment` case). The `artifact_hash` value is
derived first, over the entry exactly as presented
({{I-D.draft-mcguinness-oauth-mission}}): `typ`
`mission-intent-evidence`.

~~~ json
=============== NOTE: '\' line wrapping per RFC 8792 ===============

{
  "type": "mission-intent-admission-assertion",
  "assertion": "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FkbWlzc2\
    lvbi5leGFtcGxlLmNvbSJ9.MEUCIQDx7vector"
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
    "verified_at": "2026-11-02T07:59:39Z",
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
","verified_at":"2026-11-02T07:59:39Z"}]}
~~~

~~~ text
submission_evidence_commitment = sha-256:jnXhfVteWUHvc1-wyJOMLaVFj-d
8ewQWE4R7f0t5otY
~~~

The manifest is the always-present members above plus this
`submission_evidence_commitment`:

~~~ text
{"iss":"https://as.example.com","typ":"mission-approval-context-v1",
"value":{"approval_basis":{"activation":{"approval_event_id":"ape_8K
2nP4qV9rL3tY6sB1z"},"activation_actor":{"iss":"https://idp.example.c
om","sub":"user_3p2q8mN1a0kV7tR"},"adjudication":{"kind":"human"},"c
onsent_principal":{"iss":"https://idp.example.com","sub":"user_3p2q8
mN1a0kV7tR"},"root_commitment":"sha-256:hjXlwWBY64-RPs1Z-E_gbyklNcVi
I5c9jiyMbE4KvFM","type":"direct"},"approval_event_id":"ape_8K2nP4qV9
rL3tY6sB1z","approver":{"iss":"https://idp.example.com","sub":"user_
3p2q8mN1a0kV7tR"},"authority_hash":"sha-256:hjXlwWBY64-RPs1Z-E_gbykl
NcViI5c9jiyMbE4KvFM","authority_source":{"type":"user_delegated"},"c
lient_id":"s6BhdRkqt3","created_at":"2026-11-02T08:00:00Z","expires_
at":"2026-12-31T23:59:59Z","id":"msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9
-","intent_hash":"sha-256:6T-7s_f-mNW9UpfrrZh3r0HRJmU4My_EsNAf1C1U4r
0","issuer":"https://as.example.com","policy_version":"deploy-policy
:v17","subject":{"iss":"https://idp.example.com","sub":"user_3p2q8mN
1a0kV7tR"},"submission_evidence_commitment":"sha-256:jnXhfVteWUHvc1-
wyJOMLaVFj-d8ewQWE4R7f0t5otY"}}
~~~

~~~ text
approval_context_commitment = sha-256:iYBvYGC_LpEQkhpPiIE3S1OFINjH2d
K0jYMrCwWHvKE
~~~

**Vector 5: mutated-member rejection.** Vector 2's manifest with one
member changed, `approval_event_id` from `ape_8K2nP4qV9rL3tY6sB1z` to
`ape_9K2nP4qV9rL3tY6sB1z`, illustrating what
{{approval-context-computation}} requires a verifier to do when a
recomputed digest disagrees with a disclosed one:

~~~ text
recomputed = sha-256:4Ev4vJSv_VYjxB48tuJTsYKTSU81jfQRD48pOjazBf0
disclosed  = sha-256:pGxfIDuyBPfgpyox3J6GP477CQfUE6FS9CfHirjwwvU
~~~

The two differ, so a verifier holding the mutated record and this
disclosed vector-2 value MUST reject the reference.

**Vector 6: wrong-`typ` rejection.** Vector 2's `value` object,
unchanged, committed under `typ` `mission-approval-context-v2`
instead of `mission-approval-context-v1`:

~~~ text
correct typ (v1) = sha-256:pGxfIDuyBPfgpyox3J6GP477CQfUE6FS9CfHirjww
vU
wrong typ (v2)   = sha-256:Al8UIKy7q4_WlWem_O_6kInpGUoOp_NvPQj_YNO4z
AY
~~~

The two differ. A verifier's recompute is always fixed to
`mission-approval-context-v1`; presented with the wrong-`typ` value
as if it were vector 2's `approval_context_commitment`, it recomputes
vector 2's correct digest, finds a mismatch, and rejects under the
same rule as vector 5.

# Document History {#document-history}

\[\[ To be removed from the final specification ]]

- Immutability Witness: a mismatch between a recomputed Approval
  Context Commitment and the value an artifact disclosed shows that
  the two disagree. It is evidence that the Mission Record was altered
  only where an audit receipt independently shows the artifact
  predates the change and the disclosed value matches the registered
  approval event; a signature alone does not establish when an
  artifact was made. No requirement changed.

- An assertion that can narrow the authority, such as a model output, is
  bound to the `authority_hash` of the set it evaluated, which the
  issuer records with the activation's inputs, rather than to the
  narrowed result; Activation step 8 and the re-check follow (#1436 item
  16).

- Resolutions of the remaining #1436 questions. An assertion binds to
  the approval event's `intent_hash` as well. Policy-authorization says
  what it checks for a `policy` assertion. `contributing` lists what the
  satisfied rule counted, so a `deny` assertion never appears in it. An
  exception never lengthens its class's recency ceiling. The members of
  `evaluation` are marked as required. Evaluating Recency points at the
  one `approved_at` verification rule. Conventions names both digest
  sources. Re-checking an Evaluation defines the Relying Auditor's
  re-check. Privacy Considerations name two correlators. A policy
  version that several humans approved names its one accountable human
  as the principal.

- Four rulings on the #1436 questions (D568), each a change in
  requirements. The recording triggers bind only under a profile that
  adopts them, and a record kept voluntarily meets every requirement on
  a record. The accountable-approver rule is stated per approval basis:
  one `human` approval under `direct`, one `policy` approval naming the
  deciding policy under `governed_policy`, and the authenticated
  `approval_basis` under any other standing-consent basis. Only
  assertions of the basis's kind (under `governed_policy`, only those
  naming the deciding policy) count toward "exactly one"; other
  assertions in the consent principal's name contribute. Assertion
  Authority types `authority` for each assertion kind, and a `policy`
  assertion's principal is the human who approved the policy version.
  The JWS `typ` and `cty` are emitted with `application/` omitted and
  compared as media types.

- Editorial restructure, with no change to any requirement: Recording
  Triggers precedes the record; the record, Assertion Requirements and
  Policy-Approval Recency are split into subsections; Boundaries is
  folded into the sections it qualified; Conformance precedes Security
  Considerations; and the Approval Context Commitment test vectors are
  an appendix. Security and Privacy Considerations open with a pointer
  to the issuance profile's. Conventions defines the accountable
  assertion, the record digest, the Recording Issuer and the Relying
  Auditor. New examples show one approval per recording trigger, the
  decoded JWS protected header, a `governed_policy` activation with its
  recency computation, and the matching Consent Evidence members.

- Recording Triggers states that a Mission whose Approver differs
  from its Subject holds the first trigger, so the Enterprise Mission
  Authority Profile always records the record for it; the triggers
  are unchanged (#1196).

- Governed Policy Approval defines the `governed_policy`
  standing-consent basis: a human-approved `approval_policy` snapshot
  is the consented root, a `policy` assertion in that human's name is
  the accountable assertion, and each activation passes nine checks
  at the atomic creation commit. Assertion Requirements states the
  accountable assertion each basis requires: `human` for `direct`,
  `policy` for `governed_policy`, and the `approval_basis` record for
  the other standing-consent bases. Where the governed Mission
  populates `adjudication`, the accountable assertion's `kind` equals
  `adjudication.kind`; this document, not the OAuth binding, holds
  both rules (#1185).

- The accountable principal is the Mission Record's
  `approval_basis.consent_principal`. The Approval Context Manifest
  keeps its `approver` member, sourced from that value, so
  `mission-approval-context-v1` and vectors 1 to 6 are unchanged; the
  manifest excludes both mutable record members, `state` and
  `termination` (#705).
- Assertion Requirements and the `authority` member name a `policy`
  assertion's policy as the decision mechanism; the principal it
  matches stays the accountable approver. The policy assertion path,
  provenance and recency checks are unchanged (#1084).

- The accountable approver's assertion is `human` or `policy`, never
  `service`, and `authority` is defined for a `service` assertion,
  naming the model's identifier and version where a model produced
  the decision. A model-backed judge contributes as a governance input
  and never becomes the accountable approver. This adds a requirement.

- The Approval Context Manifest copies a recorded `ceiling_hash`
  verbatim, so the Progressive profile is an informative reference,
  meeting the maturity bound of the reference classification
  convention (a Standards-Track draft never lists an Experimental
  draft as normative). The manifest's members and both `ceiling_hash`
  presence requirements are unchanged.

- Clarified that the direct-human degenerate case presumes resolution by
  that human, not agent-invokable approval on the human's behalf (#759).

# Acknowledgments
{:numbered="false"}

The Approval Governance Record began as an approval-provenance sketch in
Mission Deferred Approval
({{I-D.draft-mcguinness-oauth-mission-approval}}). The author thanks the
Mission-Bound Authorization implementer community for feedback.
