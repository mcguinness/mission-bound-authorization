---
title: "Mission Consent Evidence for OAuth 2.0"
abbrev: "OAuth Mission Consent Evidence"
category: std

docname: draft-mcguinness-oauth-mission-consent-evidence-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - oauth
 - mission
 - consent
 - authorization
 - evidence
venue:
  github: "mcguinness/draft-mcguinness-oauth-mission"
  latest: "https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-oauth-mission-consent-evidence.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC3339:
  RFC6234:
  RFC7515:
  RFC8259:
  RFC8785:
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
  I-D.draft-mcguinness-oauth-mission-shaping:
    title: "Mission Intent Shaping for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-shaping-latest
  I-D.draft-mcguinness-oauth-mission-expansion:
    title: "Mission Expansion for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-expansion-latest
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

Mission-Bound Authorization for OAuth 2.0 commits the approved Mission
Intent and Authority Set, but does not commit the exact consent
disclosure shown to the Approver. This document defines an OPTIONAL
Consent Evidence profile. It specifies a structured consent disclosure
object, a `consent_rendering_hash` integrity anchor, and a signed
Consent Evidence object that records the structured disclosure the
Authorization Server rendered or committed to rendering, which Approver
it recorded as deciding, which Mission authority the disclosure
corresponded to, and which notices or material risks it carried. The
profile lets an auditor reconstruct the recorded approval surface
without making the disclosure itself an authority grant.

--- middle

# Introduction {#introduction}

Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} (the "issuance profile") binds a
Mission to an approval event and commits two objects: the approved
Mission Intent and the approved Authority Set. It deliberately notes a
remaining gap: the exact consent disclosure rendered to the Approver is
not itself committed. A faulty or malicious rendering layer could show
a narrower task than the Authority Set actually records.

This document narrows that gap. It defines a structured consent
disclosure object and a Consent Evidence object. The disclosure object
is what the Authorization Server renders or commits to rendering. The
evidence object records the approval event, the rendering context, the
Mission anchors, and an integrity envelope over the evidence.

This profile commits the structured disclosure that the Authorization
Server says it rendered, and binds it to the same Mission anchors used
for authority. It does not, and cannot, prove that the pixels actually
presented to the Approver matched that structured object, that the
Approver read or understood it, or that the rendering layer was honest.
A faulty or malicious rendering layer that lies about what it displayed
remains outside the reach of any server-side commitment. What this
profile provides is a durable, integrity-protected record that ties a
specific structured disclosure to a specific approval decision and
Authority Set, so that divergence between the recorded disclosure and
the enforced authority becomes detectable in audit.

How much a deployment can narrow the rendering gap is not all-or-nothing.
This profile defines a ladder of rendering assurance
({{rendering-assurance}}) whose rungs move the trust from an unbounded,
unverifiable rendering layer toward the Approver's own authenticator
signing the exact disclosure commitment. No rung proves what pixels a
human perceived, but the higher rungs shrink the trusted rendering base
to a small, attestable one and let the deployment pick the assurance its
threat model needs.

Consent Evidence does not grant authority. Authority remains the
approved Mission and its Authority Set under
{{I-D.draft-mcguinness-oauth-mission}}. Consent Evidence lets auditors
verify that the recorded approval surface corresponded to the authority
later enforced.

# Scope

This document defines:

- the consent disclosure object ({{consent-disclosure}});
- the `consent_rendering_hash` commitment ({{consent-rendering-hash}});
- the Consent Evidence object ({{consent-evidence}});
- binding rules for initial Mission approval and expansion approval
  ({{binding-to-mission}});
- retention and audit reconstruction requirements ({{audit}}); and
- conformance for a Consent-Evidence-capable Mission Issuer
  ({{conformance}}).

This document does not define user-interface layout, a legal consent
standard, or any new OAuth grant. It does not change the Authority Set
or Mission lifecycle.

## Evidence Model {#evidence-model}

This profile separates three artifacts:

1. the Mission Intent and Authority Set, which define what is being
   approved under {{I-D.draft-mcguinness-oauth-mission}};
2. the Consent Disclosure object, which defines in structured form what
   the Authorization Server rendered or committed to rendering for the
   Approver; and
3. the Consent Evidence object, which records the approval or decline
   event and integrity-protects the disclosure commitment.

Only the approved Mission grants authority. The disclosure and evidence
objects prove the approval surface and are audit artifacts.

# Conventions and Terminology {#conventions}

{::boilerplate bcp14-tagged}

This document uses JSON {{RFC8259}} for the disclosure and evidence
objects. JCS {{RFC8785}} is used when computing
`consent_rendering_hash`.

The terms Mission, Mission Intent, Authority Set, Mission Issuer,
Approver, and approval event are used as defined in
{{I-D.draft-mcguinness-oauth-mission}}.

Consent Disclosure:
: A structured object describing the approval surface rendered to the
  Approver.

Consent Evidence:
: A durable, integrity-protected record of the consent disclosure and
  approval event.

# Consent Disclosure Object {#consent-disclosure}

A Consent Disclosure object has these members:

`disclosure_id`:
: REQUIRED. A string. Unique identifier for this rendered disclosure.

`template_id`:
: REQUIRED. A string identifying the disclosure template.

`template_version`:
: REQUIRED. A string identifying the template version.

`locale`:
: REQUIRED. A string identifying the locale used for presentation.

`mission_summary`:
: REQUIRED. An object. The human-readable task summary presented to
  the Approver.

`authority_summary`:
: REQUIRED. An object. The rendered summary of resources, actions,
  constraints, delegation, expiry, and material consumption bounds. This
  is the consent object: per the issuance profile
  ({{I-D.draft-mcguinness-oauth-mission}}), the Approver consents to the
  derived authority, with `mission_summary` as context. A disclosure
  that renders `mission_summary` without a faithful `authority_summary`
  does not conform.

`material_notices`:
: REQUIRED. An array. Notices that materially affect the Approver's
  decision, such as irreversible actions, external commitments,
  privileged administration, cross-domain disclosure, broad reads, or
  delegation.

`risk_summary`:
: REQUIRED. An object summarizing action classes and risk dimensions
  presented to the Approver. It MUST identify at least irreversible
  actions, external commitments, privileged administration, broad or
  bulk reads, cross-domain disclosure, delegation, and consumption
  bounds when present.

`constraint_provenance`:
: OPTIONAL. An array attributing bounds in the Authority Set to the
  authority that imposed them, so the Approver and a later auditor see
  not just a bound but whose rule it is: a delegator ceiling and a court
  order read differently when one fails. Each entry has:

  `applies_to`:
  : REQUIRED. An object identifying the bound, by the Authority Set
    entry's `resource` and the `constraint` key or `action` it concerns.

  `source`:
  : REQUIRED. A string naming the imposing authority. Recommended,
    non-exhaustive values are `subject`, `delegator`, `platform`,
    `regulatory`, and `judicial`; the value is descriptive and a
    deployment MAY use another.

  `source_uri`:
  : OPTIONAL. A string. A URI identifying the imposing instrument or
    policy, including a URN for a non-dereferenceable instrument such as
    `urn:court:order:2026-55`.

  `constraint_provenance` is disclosure and audit material: it is
  rendered for consent and committed by `consent_rendering_hash`
  ({{consent-rendering-hash}}), but it grants no authority, is not
  carried on any token, and is not enforced. It is the consent-layer home
  for constraint authorship; the Authority Set itself
  ({{I-D.draft-mcguinness-oauth-mission}}) carries only the bound, not
  its author.

  ~~~ json
  [
    { "applies_to": { "resource": "https://erp.example.com",
        "constraint": "max_amount_usd" },
      "source": "delegator",
      "source_uri": "https://corp.example/policy/spend" },
    { "applies_to": { "resource": "https://erp.example.com",
        "action": "journal-entries.write" },
      "source": "judicial", "source_uri": "urn:court:order:2026-55" }
  ]
  ~~~

`delegation_summary`:
: REQUIRED when the Authority Set permits delegation. An object
  describing who may receive delegated authority, maximum depth, and
  whether child Missions or further delegation are permitted.

`runtime_summary`:
: OPTIONAL. An object describing runtime enforcement expectations shown
  to the Approver, such as per-action checks, status freshness, audit
  evidence, or human-review steps.

`subject`:
: REQUIRED when the Approver is not the Subject. The rendered
  identification of the Subject on whose behalf authority is granted.

`approver`:
: REQUIRED. The rendered identity of the Approver.

`source_hashes`:
: REQUIRED. An object containing the `intent_hash` and
  `authority_hash` values the disclosure corresponds to. The disclosure
  object carries these two hashes rather than the full `mission`
  container ({{consent-evidence}}) because it is constructed before
  approval commits the Mission: the Mission `id` and lifecycle do not
  yet exist, and the disclosure must commit only to the proposed Intent
  and Authority Set it actually renders. The Consent Evidence object,
  recorded at or after the decision, carries the resolved `mission`
  container with `id`, `origin`, and the same anchors.

`shaping_evidence_hash`:
: OPTIONAL. A string. A commitment to Shaping Evidence when shaping was
  used ({{I-D.draft-mcguinness-oauth-mission-shaping}}).

`predecessor`:
: OPTIONAL. A string. The predecessor Mission identifier when this
  disclosure is for an expansion approval
  ({{I-D.draft-mcguinness-oauth-mission-expansion}}).

`display_context`:
: REQUIRED. An object containing presentation context, including at
  least `channel` (for example, `web`, `device`, `api`, or
  `admin_console`) and `rendered_at`.

`approver_actions`:
: OPTIONAL. An array describing explicit approver interactions required
  by policy, such as checking a high-risk notice or confirming an
  expansion delta.

A Consent Disclosure object MUST NOT omit material authority. If the
Authority Set includes delegation, external commitments, irreversible
actions, privileged administration, cross-domain authority, or
consumption bounds, the disclosure MUST include a material notice or a
rendered authority summary entry covering that fact.

## Material Notice Requirements {#material-notices}

A material notice is required for each of these conditions when present
in the proposed Authority Set or Mission context:

- delegation to another actor or child Mission;
- authority that crosses an organizational or issuer boundary;
- irreversible action;
- external commitment;
- privileged administration;
- broad, bulk, export-like, or privacy-sensitive read;
- consumption bounds that can be exhausted by the agent;
- Mission expansion that widens authority;
- authority that can affect a party other than the Subject or
  Approver; and
- runtime enforcement gaps disclosed by the deployment.

Each notice MUST identify the Authority Set entry or entries it
describes. A generic warning that "this may be risky" is not sufficient
for this profile.

# `consent_rendering_hash` {#consent-rendering-hash}

`consent_rendering_hash` is the integrity-anchor encoded form of the
SHA-256 {{RFC6234}} of the JCS {{RFC8785}} canonical bytes of this
envelope:

~~~
{
  "typ": "mission-consent-disclosure",
  "iss": <mission.origin>,
  "value": <Consent Disclosure object>
}
~~~

The value uses the same algorithm-agile integrity-anchor encoding the
issuance profile {{I-D.draft-mcguinness-oauth-mission}} defines for
`intent_hash` and `authority_hash`: a collision-resistant hash-name
prefix and the base64url digest, for example `sha-256:...`. A consumer
MUST treat the prefix as identifying the hash function and MUST NOT
assume SHA-256; this lets the commitment migrate to a stronger function
without ambiguity.

The hash commits the disclosure object, not pixels or browser state. A
deployment MAY additionally retain screenshots or UI telemetry, but the
interoperable commitment is the structured disclosure object.

So that the committed object can be related to what a human would see,
the rendering SHOULD be a deterministic function of the disclosure
object and its `template_id`, `template_version`, and `locale`: the same
inputs MUST produce the same rendered form, and the named template
MUST be retrievable or reconstructable by an authorized auditor for the
retention period ({{audit}}). An auditor can then re-render the recorded
disclosure into the form the Approver should have been shown. This does
not prove what was displayed, but it reduces the gap from "the rendering
layer showed something unverifiable" to "did the rendering layer execute
a published deterministic template," which the higher rungs of
{{rendering-assurance}} then address.

The Mission Issuer SHOULD record `consent_rendering_hash` on the
Mission record. When the Mission claim is extended to carry the value,
it MUST carry the same prefixed integrity-anchor form, and consumers
MUST treat it as audit data only; it MUST NOT grant or widen
authority.

The Consent Disclosure object MUST be constructed after Authority Set
derivation and before approval. If the Authority Set changes after the
disclosure is constructed, the Mission Issuer MUST discard the
disclosure and construct a new one; it MUST NOT reuse the prior
`consent_rendering_hash`.

# Rendering Assurance {#rendering-assurance}

The commitment of {{consent-rendering-hash}} records what disclosure the
Authorization Server says it rendered; it cannot by itself prove what a
human perceived. This is the what-you-see-is-what-you-sign problem. This
profile does not close it with a server-side commitment, which is
impossible, but defines a ladder a deployment climbs as far as its
threat model requires. Each rung shrinks the trusted rendering base; to
claim a rung a deployment satisfies it and records the corresponding
evidence. The rungs are cumulative: claiming a rung requires satisfying
the rungs below it, so a Rung 3 confirmation is over a disclosure that
is also deterministically renderable (Rung 1) and an auditor can
re-render exactly what the confirmation signed.

Rung 0, Recorded disclosure:
: The baseline of {{consent-rendering-hash}}: the structured disclosure
  is committed and bound to the Mission anchors. Proves the AS recorded
  this disclosure for this authority; proves nothing about what was
  shown.

Rung 1, Deterministic rendering:
: The rendering is a deterministic function of the disclosure object and
  its committed template ({{consent-rendering-hash}}), so an auditor can
  re-render the intended form. The open question narrows to whether the
  rendering layer faithfully executed a published template.

Rung 2, Attested rendering:
: The Consent Evidence carries a `rendering_attestation`
  ({{consent-evidence}}): evidence that an attested, identified rendering
  component (a first-party AS-hosted consent surface, or a renderer
  attested by the platform or a trusted execution environment) produced
  the rendering. The trusted base shrinks from any rendering layer to an
  attested one.

Rung 3, Approver confirmation:
: The Consent Evidence carries a `rendering_confirmation`
  ({{consent-evidence}}): a signature produced by the Approver's
  authenticator over the `consent_rendering_hash` at approval, binding
  the approval credential itself to the exact committed disclosure. The
  claim that the Approver approved this disclosure then rests on the
  Approver's authenticator, not on the Authorization Server. This is the
  what-you-see-is-what-you-sign rung, as in authenticator
  transaction-confirmation schemes. A deployment SHOULD reach this rung
  for a Mission whose Authority Set carries a high-risk material-notice
  class ({{material-notices}}): irreversible actions, external
  commitments, privileged administration, or cross-domain disclosure.

Rung 4, Out-of-band confirmation:
: For the most material actions, confirmation is obtained at execution
  time on a channel the rendering layer does not control, as the
  action-bound approval of the runtime layer
  ({{I-D.draft-mcguinness-oauth-mission-runtime}}); a rendering layer
  would then have to compromise two independent paths. That is a
  runtime-layer mechanism recorded as its own evidence; this profile
  records the approval-time rungs above.

No rung proves the Approver perceived or understood the disclosure; a
compromised authenticator or trusted execution environment, or an
Approver who confirms without reading, remains outside reach, as for any
electronic-signature scheme. What the ladder provides is a verifiable,
bounded reduction of the rendering trust base: at Rung 3 the claim that
the Approver approved a specific disclosure is verifiable up to trust in
the Approver's authenticator, rather than in an arbitrary rendering
layer.

# Consent Evidence Object {#consent-evidence}

A Consent Evidence object has these members:

`evidence_id`:
: REQUIRED. A string. Unique evidence identifier.

`mission`:
: REQUIRED. An object binding the evidence to what was approved. Its
  shape depends on `decision`, because a Mission exists only after an
  approval ({{I-D.draft-mcguinness-oauth-mission}}):
  - When `decision` is `approved`, it contains `id`, `origin`,
    `intent_hash`, `authority_hash`, and, when this profile records it
    on the Mission, `consent_rendering_hash`.
  - When `decision` is `declined`, no Mission was created
    ({{declined-events}}), so there is no `id`. It instead contains
    `origin` and the `intent_hash` and `authority_hash` the disclosure
    corresponded to, matching the disclosure object's `source_hashes`
    ({{consent-disclosure}}). It MUST NOT contain `id`.

  This descriptor follows the evidence-descriptor convention of the
  issuance profile ({{I-D.draft-mcguinness-oauth-mission}}): it is the
  `mission` claim shape extended with the collision-resistantly named
  audit members `intent_hash` and `consent_rendering_hash`, and it is
  not authority-bearing on its own.

`approver`:
: REQUIRED. An object identifying the authenticated Approver.

`subject`:
: REQUIRED when different from the Approver. An object identifying the
  Subject.

`client`:
: REQUIRED when known. An object identifying the client or agent
  requesting the Mission.

`authentication_context`:
: REQUIRED. An object recording the `acr`, `amr`, and authentication
  time used for the approval event when available.

`disclosure`:
: REQUIRED. The Consent Disclosure object, or an object containing a
  durable reference and the `consent_rendering_hash`.

`rendering_attestation`:
: OPTIONAL. An object. Evidence that an attested, identified rendering
  component produced the rendering shown to the Approver (Rung 2,
  {{rendering-assurance}}). Its members are deployment-defined and
  identify the attested component and its attestation; this profile
  fixes the role, not the attestation format.

`rendering_confirmation`:
: OPTIONAL. An object. A confirmation produced by the Approver's
  authenticator at approval (Rung 3, {{rendering-assurance}}). To bind
  the trust to the Approver rather than the Authorization Server, it
  MUST sign the `consent_rendering_hash` together with a per-approval
  value (the `evidence_id`, or a nonce echoed in
  `authentication_context`), so a captured confirmation cannot be
  replayed into another record, and it MUST carry or reference an
  authenticator credential that the verifier can confirm is bound to the
  recorded `approver`. This profile fixes what is signed and bound, not
  the authenticator protocol. A deployment SHOULD include it for a
  high-risk material-notice class ({{material-notices}}). When present,
  a verifier MUST check it as part of {{integrity}} and MUST treat a
  confirmation that does not verify, or whose authenticator is not bound
  to the recorded `approver`, as an integrity failure.

`approved_at`:
: REQUIRED when `decision` is `approved`. An RFC 3339 {{RFC3339}}
  timestamp.

`declined_at`:
: REQUIRED when `decision` is `declined`. An RFC 3339 timestamp.

`decision`:
: REQUIRED. One of `approved` or `declined`.

`decline_reason`:
: OPTIONAL. A string. Present when `decision` is `declined` and the
  deployment records a reason.

`policy_version`:
: REQUIRED when known. The approval policy version in effect at the
  approval event.

`sequence`:
: REQUIRED. An integer. A per-Mission-Issuer consent evidence sequence
  value or another deployment-defined monotonic indicator sufficient to
  reconstruct evidence order.

`evidence_envelope`:
: REQUIRED when retained as a portable record. An object carrying
  `format` and `value`. This document defines `jws-compact`, a JWS
  Compact Serialization {{RFC7515}} over the JCS canonical bytes of the
  Consent Evidence object with `evidence_envelope` removed.

Example:

~~~ json
{
  "evidence_id": "cns_7rP2kL9mQ4",
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "origin": "https://as.example.com",
    "intent_hash": "sha-256:wQ7p4LHnX9Md0LqJ6sZJ8b8mZ3rN2xT5pV4lE6sQqYY",
    "authority_hash": "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ",
    "consent_rendering_hash":
      "sha-256:CnS3nT9sQ7nM2vL4tY6bD1eF8jC5wH0pV2nR3kQ4xVz"
  },
  "approver": {
    "iss": "https://idp.example.com",
    "sub": "alice"
  },
  "authentication_context": {
    "acr": "urn:example:acr:phishing-resistant",
    "amr": ["pwd", "hwk"],
    "auth_time": "2026-06-30T17:54:00Z"
  },
  "approved_at": "2026-06-30T17:55:00Z",
  "decision": "approved",
  "policy_version": "approval-policy:v12",
  "sequence": 88127,
  "disclosure": {
    "disclosure_id": "disc_4pQ9z",
    "consent_rendering_hash":
      "sha-256:CnS3nT9sQ7nM2vL4tY6bD1eF8jC5wH0pV2nR3kQ4xVz"
  },
  "evidence_envelope": {
    "format": "jws-compact",
    "value": "eyJhbGciOiJFUzI1NiIsImtpZCI6ImNvbnNlbnQt..."
  }
}
~~~

## Integrity and Verification {#integrity}

When `evidence_envelope.format` is `jws-compact`, the protected header
MUST identify a signing key controlled by the Mission Issuer or an
evidence service authorized by the Mission Issuer. A verifier:

1. removes `evidence_envelope`;
2. canonicalizes the remaining Consent Evidence object with JCS;
3. verifies the JWS payload against those bytes;
4. verifies the signing key against the Mission Issuer's published key
   material or configured trust anchors; and
5. when `decision` is `approved`, verifies that the Mission anchors in
   `mission` match the Mission record being audited. When `decision` is
   `declined` there is no Mission record ({{declined-events}}); the
   verifier instead confirms the `mission` descriptor carries `origin`
   and the two `source_hashes` anchors and no `id`; and
6. when `rendering_confirmation` is present
   ({{rendering-assurance}}), verifies it against the recorded
   `approver`'s authenticator and over the `consent_rendering_hash`
   bound to the per-approval value, and treats a confirmation that does
   not verify, or whose authenticator is not bound to the recorded
   `approver`, as an integrity failure; and
7. when `rendering_attestation` is present ({{rendering-assurance}}),
   validates the attested component identity and its attestation against
   the verifier's configured trust anchors, and treats an attestation it
   cannot validate as unverified (the evidence then asserts no rung above
   the one the verifier can check, not an integrity failure of the
   record).

The absence of `rendering_confirmation` or `rendering_attestation` is
not a failure; it means the evidence asserts no rung above the rendering
the AS recorded.

Steps 1 through 5 establish the integrity of the evidence record itself
and rely only on the record, since `consent_rendering_hash` is carried
inside the signed `mission`. Reconstructing the disclosure is a separate
step that depends on retrieval: when the disclosure object is inlined, a
verifier recomputes `consent_rendering_hash` over it and compares; when
it is carried by reference ({{minimization}}), the verifier retrieves it
and verifies it against `consent_rendering_hash`. A verifier MUST NOT
treat a disclosure that is merely unretrievable as an integrity failure
of the evidence record; failure to retrieve a referenced disclosure
within the retention window is an audit failure ({{audit}}), not a
signature or anchor failure.

Evidence whose envelope format is unsupported MUST be rejected rather
than accepted without verification.

# Binding to Mission Approval {#binding-to-mission}

At an approval event, a Consent-Evidence-capable Mission Issuer MUST:

1. derive the Authority Set and compute `intent_hash` and
   `authority_hash` under {{I-D.draft-mcguinness-oauth-mission}};
2. construct the Consent Disclosure object from that exact Authority
   Set and Mission Intent;
3. compute `consent_rendering_hash`;
4. render the disclosure to the Approver;
5. record Consent Evidence for `approved` or `declined`; and
6. when approved, bind the Mission record to the
   `consent_rendering_hash`.

For expansion approvals, the disclosure MUST identify the predecessor
Mission and distinguish retained authority from newly requested
authority.

## Declined Approval Events {#declined-events}

Declined approval events are security-relevant. A deployment claiming
this profile MUST record Consent Evidence when an Approver declines a
Mission or expansion request. The evidence MAY omit sensitive
free-form decline text, but it MUST record the disclosure commitment,
decision, Approver, time, and policy version when known.

Declined evidence MUST NOT create a Mission, Mission claim, token, or
authority. It exists to prevent silent retry, coercion, and rendering
confusion from being invisible to audit.

## Expansion and Delta Disclosure {#expansion-disclosure}

When the approval event is for Mission Expansion, the Consent
Disclosure object MUST distinguish:

- authority retained from the predecessor;
- authority newly added;
- authority removed or narrowed;
- changes to Mission expiry;
- changes to delegation or child-Mission rights; and
- the predecessor Mission identifier.

An expansion disclosure that renders only the final Authority Set
without the delta is not conforming to this profile, because it fails
to show what is being widened.

# Audit Reconstruction {#audit}

A deployment claiming this profile MUST retain enough information for
an authorized auditor to reconstruct:

- the Mission Intent and Authority Set approved;
- the Consent Disclosure object;
- the template, template version, and locale;
- the material notices presented;
- the Approver, Subject, and approval authentication context; and
- the integrity path from Consent Evidence to the Mission record.

Retention MUST last at least as long as the Mission's audit horizon.

## Minimization and Redaction {#minimization}

The portable Consent Evidence object MAY contain a durable reference to
the full Consent Disclosure object rather than the full object itself,
provided the reference is access-controlled and the evidence includes
`consent_rendering_hash`. A verifier with authorization MUST be able to
retrieve or reconstruct the disclosure for the retention period.

Free-form task text and approver comments SHOULD be redacted or stored
by reference when not required for ordinary audit.

# Conformance {#conformance}

A conforming Consent-Evidence-capable Mission Issuer MUST:

- construct a Consent Disclosure object for each approval event;
- compute `consent_rendering_hash`;
- record Consent Evidence for approval and decline decisions;
- bind approved Mission records to `consent_rendering_hash`;
- include material notices for high-risk authority; and
- retain evidence for audit reconstruction.

A conforming verifier of Consent Evidence MUST implement the checks in
{{integrity}} and MUST treat failure to retrieve a referenced
disclosure during the retention window as an audit failure.

# Security Considerations {#security-considerations}

## Rendering Confusion

The primary threat is rendering confusion: the Approver sees one thing
while the Mission records another. This profile mitigates that by
committing a structured disclosure object to the same Mission anchors
used for authority, so a disclosure that understates the Authority Set
is detectable in audit. It does not eliminate the threat: a rendering
layer that displays pixels inconsistent with the structured disclosure
it commits remains outside any server-side commitment ({{introduction}}).
The assurance ladder of {{rendering-assurance}} is how a deployment
reduces this threat by degree: deterministic rendering makes the
intended form re-renderable (Rung 1), a rendering attestation binds an
attested renderer (Rung 2), and an Approver confirmation signature over
the `consent_rendering_hash` (Rung 3) moves the trust from the rendering
layer to the Approver's authenticator. A deployment that needs assurance
that the Approver approved a specific disclosure SHOULD reach Rung 3 for
its high-risk classes; no rung proves perception, which remains outside
reach for any electronic-signature scheme.

## Template Downgrade

An attacker could use an outdated or less explicit template. The
Consent Disclosure object includes `template_id` and
`template_version`; deployments SHOULD reject templates not approved
for the action classes being authorized.

## Evidence Does Not Grant Authority

Consent Evidence proves what was shown and decided. It MUST NOT be
accepted as a token, grant, or substitute for the Mission's
`authority_hash`.

## Decline Suppression

An attacker could repeatedly reshape and resubmit a declined Mission to
obtain approval through fatigue. Recording declined events lets
deployments detect repeated attempts against the same task, requester,
or Authority Set.

## Incomplete Material Notices

If material notices omit high-risk authority, the Approver's consent
may not be meaningful. Deployments SHOULD test disclosure templates
against Authority Set fixtures and reject templates that cannot render
all material notice classes.

# Privacy Considerations {#privacy-considerations}

Consent Evidence can contain sensitive task descriptions, business
context, approver identity, subject identity, and high-risk authority
details. Deployments SHOULD protect it at least as strongly as Mission
records and runtime evidence. Where possible, portable records SHOULD
carry hashes or references rather than full rendered text, while still
allowing authorized audit reconstruction.

# IANA Considerations {#iana}

This document makes no IANA request.

Future versions may request registration for
`application/mission-consent-evidence+json` if portable exchange of
Consent Evidence becomes an interoperability requirement. Until such a
registration exists, deployments using this media type do so by local
agreement.

--- back

# Acknowledgments
{:numbered="false"}

This document is part of the Mission-Bound Authorization for OAuth 2.0
set and binds the approval surface to the Mission authority record.
