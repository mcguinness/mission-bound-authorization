---
title: "Mission Work Products"
abbrev: "OAuth Mission Work Products"
category: exp

docname: draft-mcguinness-oauth-mission-work-products-latest
submissiontype: IETF
workgroup: Web Authorization Protocol
number:
date:
consensus: true
v: 3
keyword:
 - oauth
 - mission
 - agent
 - authorization
 - provenance
 - work products
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-work-products.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC3339:
  RFC6234:
  RFC6838:
  RFC7515:
  RFC7519:
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
  I-D.draft-mcguinness-mission-architecture:
    title: "An Architecture for Mission-Bound Authorization"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-architecture.html
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
  I-D.draft-mcguinness-oauth-mission-cross-domain:
    title: "Mission Cross-Domain Projection for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-cross-domain.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-continuation:
    title: "Mission Continuation: Authorization Continuity for Mission-Bound Authorization"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-continuation.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-security-model:
    title: "Mission-Bound Authorization: Security Model and Trusted Base"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-security-model.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-audit:
    title: "Mission Transparency: SCITT Registration of Mission Evidence"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-audit.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  IN-TOTO:
    target: https://in-toto.io/
    title: "in-toto: A Framework to Secure the Integrity of the Software Supply Chain"
    author:
      -
        org: Cloud Native Computing Foundation
    date: 2024
  SLSA:
    target: https://slsa.dev/spec/
    title: "Supply-chain Levels for Software Artifacts (SLSA)"
    author:
      -
        org: Open Source Security Foundation
    date: 2023

--- abstract

Agents produce durable artifacts, files, messages, memory entries,
queue events, packages, and directory names, that other agents and
Missions later read. An artifact can carry knowledge across a boundary,
but it must not carry authority across with it. This document defines,
as an experimental companion to Mission-Bound Authorization for OAuth
2.0, how a work product records where it came from without becoming a
grant. It states one invariant: no authority is acquired by information
propagation alone. It defines a policy-free work-product provenance
object that attributes an artifact to the approved work under which it
came into existence, and a non-transitive Mission-to-Mission handoff
rule: an artifact crossing into a receiving Mission is input, and the
receiving Mission re-evaluates any proposed action under its own
Authority Set. Provenance answers "under what approved work did this
come into existence"; it never answers "what may the reader do."

--- middle

# Introduction {#introduction}

Agentic work at machine speed produces and consumes shared artifacts
across runtimes and Missions: a file written for a later step, a message
posted to a channel, an entry added to shared memory, an event placed on
a queue, a package published to a registry. Each artifact records what
some earlier work discovered or decided. None of them is a credential,
and none of them may act as one.

The family already enforces this discipline on the credential plane. A
continuation handle grants nothing and is not a credential
({{I-D.draft-mcguinness-oauth-mission-continuation}}); an Active Mission
is not ambient standing authority, so each action is re-checked
({{I-D.draft-mcguinness-mission-security-model}}); revocation is
possession-independent, so holding a credential is not holding authority
({{I-D.draft-mcguinness-mission-architecture}}). This document extends
the same discipline to the artifact plane: an agent may inherit another
agent's knowledge, and never inherits another agent's authority.

Its place in the family is the artifact-scoped companion to the
execution-time-evidence continuity of Mission Continuation
({{evidence-continuity}}). It defines no new token type, grant type, or
endpoint. It defines one invariant ({{invariant}}), a provenance object
that attributes an artifact ({{provenance}}), and the rule that makes
the invariant hold when an artifact crosses between independent Missions
({{handoff}}).

# Status: An Experimental Extension {#optional-status}

This document is optional and experimental: adopt it for evaluation, not
as a stable interface. No Standards-Track document depends on it.

A Mission Issuer or deployment that does not implement this document is
a fully conforming issuance-profile deployment
({{I-D.draft-mcguinness-oauth-mission}}). Nothing here places a new
requirement back on the issuance profile, and this document adds no
constraint to the core's `mission_resource_access`. The provenance
object and the handoff rule are companion mechanisms that a deployment
adopts where its agents share durable work products.

# Relationship to Other Profiles {#relationship}

This document depends normatively on the issuance profile
{{I-D.draft-mcguinness-oauth-mission}} and is not implementable alone.
It uses Mission, Authority Set, approval event, `active`, derivation,
and the subset rule as the issuance profile defines them.

The invariant of {{invariant}} is not a new axiom. It is the
artifact-plane reading of a claim the issuance profile already makes on
the credential plane: authority exists only by derivation for a Mission,
so no possessed thing, credential or artifact, substitutes for the
Mission's live gate. Alignment with a forthcoming core Security
Considerations statement of this property is anticipated; this document
states the property for work products and imposes nothing new on the
core.

Child delegation ({{I-D.draft-mcguinness-oauth-mission-child-delegation}})
is the legitimate authority path this document points to: where an agent
needs authority to act on what it read, it obtains a Child Mission
bounded by the parent under the subset rule, never authority read off
the artifact. Cross-domain projection
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}) is contrasted in
{{handoff}}: it preserves the same Mission across a trust boundary,
where this document governs handoffs between independent Missions. The
architecture ({{I-D.draft-mcguinness-mission-architecture}}) promotes
the quarantine pattern to a normative cross-Mission handoff rule and
hosts the conjunctive gating model this document extends. The security
model ({{I-D.draft-mcguinness-mission-security-model}}) catalogs the
threat this rule addresses.

# Conventions and Terminology {#conventions}

{::boilerplate bcp14-tagged}

This document uses the terms Mission, Authority Set, approval event,
`active`, derivation, and subset rule from
{{I-D.draft-mcguinness-oauth-mission}}. It additionally defines:

Work Product:
: A durable, shared artifact an agent produces under a Mission: a file,
  a message, a memory entry, a queue event, a package, a directory name,
  or another artifact a later agent or Mission can read.

Producing Mission:
: The Mission under whose approved work a work product came into
  existence.

Receiving Mission:
: A Mission whose agent reads a work product that a different Mission
  produced.

Work Product Provenance:
: The object of {{provenance}} that attributes a work product to its
  Producing Mission. It is an attribution claim, never an authority
  claim.

# The Work Product Invariant {#invariant}

This document states one invariant, in normative language so
conformance to it is testable ({{conformance}}):

- No authority is acquired by information propagation alone.
- An agent MAY inherit another agent's knowledge. A consumer MUST NOT
  treat a work product, or its Work Product Provenance object, as a
  grant of the producing agent's authority.
- Information MAY cross a boundary without authority crossing with it.
  A component on that path MUST NOT construe the crossing of
  information as also conferring authority.

The invariant extends the credential-plane claims of {{relationship}} to
the artifact plane; it does not contradict or replace them. The
provenance object of {{provenance}} makes an artifact's origin legible,
and the handoff rule of {{handoff}} keeps that origin from becoming a
grant.

# Work Product Provenance {#provenance}

A work product MAY carry a Work Product Provenance object attributing it
to the approved work under which it came into existence. The object is a
JSON object {{RFC8259}} with these members and only these:

mission_id:
: REQUIRED. The Producing Mission.

deployment_id:
: REQUIRED. The Agent Deployment that produced the work product.

producer:
: REQUIRED. The producing principal or agent under that Mission.

created_at:
: REQUIRED. The production time, as an {{RFC3339}} date-time.

parent_artifact:
: OPTIONAL. A back-reference to the work product this one derived from,
  forming a provenance chain.

Where a work product carries a Work Product Provenance object, that
object MUST be attached by a trusted mediator acting for the Producing
Mission, such as its Agent Deployment's execution environment or the
Mission Issuer, from that mediator's own record of which Mission's
approved work was executing when the artifact was produced. The
producing agent MUST NOT self-author or self-assert its own Work
Product Provenance: an agent attaching its own attribution could claim
an origin under approved work it never executed, an authority-bearing
forgery the custody boundary exists to prevent. This is a rule about
who may write the object, not about what it contains: the object
still carries only the five members above, and none of them is a
permission.

The object is policy-free by construction: it carries no authority, no
constraint, no classification, and no permission. Its sole function is
to answer one question, "under what approved work did this information
come into existence," and never the question "what may the reader do."
A reader can therefore distinguish a provenance claim, "produced by an
agent executing Mission M," from an authority claim, "Mission M
authorized me to do what this proposes," which the object never makes.

The `producer` member names the producing Mission's principal or agent.
This differs from the producer of an evidence record elsewhere in the
suite, which is the principal or component that emitted the record, a
Mission Issuer, a PDP, a PEP, or an executor
({{I-D.draft-mcguinness-mission-audit}}). The two are distinct: this
object attributes the work product to the Producing Mission, not to the
component that emitted a record.

Work Product Provenance is attribution metadata carried with the work
product, not one of the suite's evidence objects: it records where the
artifact came from, not what was done. Where a deployment retains it, it
is recorded as Mission evidence attributed to the Producing Mission, the
producer of Mission evidence in the audit sense
({{I-D.draft-mcguinness-mission-audit}}), and disclosed under the access
rules for that deployment's Mission evidence. An implementation MAY
realize it as a discriminated kind on a shared evidence structure; this
document defines only the members above and requires no new media type.

# Non-Transitive Mission-to-Mission Handoff {#handoff}

Attributing a work product does not authorize a reader to act on it. The
rule that keeps the invariant of {{invariant}} holding when a work
product crosses from its Producing Mission into an independent Receiving
Mission is:

- A work product crossing into a Receiving Mission is input, not
  authority.
- The Receiving Mission MUST re-evaluate any proposed action under its
  own Authority Set before acting on a work product it reads.
- The Producing Mission's authority MUST NOT be treated as transferred
  through the work product by copying, referencing, embedding, or
  communicating it.
- Where an agent needs authority to act on what it read, that authority
  MUST be obtained only through the authority plane, a Child Mission
  request bounded by the parent under the subset rule
  ({{I-D.draft-mcguinness-oauth-mission-child-delegation}}) or another
  authorized Mission transition, and MUST NOT be taken from the work
  product.

The handoff is non-transitive: authority earned by the Producing Mission
does not accrue to the Receiving Mission because the two share an
artifact. The Receiving Mission holds exactly the authority its own
approval derived, and reading a work product neither widens that set nor
substitutes for its live gate.

## Contrast with Cross-Domain Projection {#cross-domain-contrast}

Cross-domain projection preserves the same Mission across a trust
boundary: the projected credential carries a subset of one Mission's
authority into another domain, and the work stays under that one Mission
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}). The handoff of
this section is different in kind. It is between independent Missions,
and the Receiving Mission re-evaluates under its own Authority Set
rather than continuing the producer's. A work product is not a
projection: it moves information, not the Mission.

# Relationship to the Execution-Time Evidence Continuity {#evidence-continuity}

Mission Continuation keeps three continuities apart: identity
continuity, authorization continuity, and execution-time evidence
({{I-D.draft-mcguinness-oauth-mission-continuation}}). Work provenance
is the artifact-scoped companion to the third, and does not rename it.

Execution-time evidence answers "what was done": it is action-scoped
and recorded against the Mission at each continued hop. Work provenance
answers "under what approved work did this artifact come into
existence": it is artifact-scoped and attributed to the Producing
Mission. The two
sit beside each other. Evidence ties an action back to the Mission that
took it; provenance ties an artifact back to the Mission that produced
it. Neither answers what a reader of the artifact may do; that remains
the Receiving Mission's Authority Set to decide ({{handoff}}).

# Work Product Binding {#binding}

A work product MAY additionally carry a Work Product Binding: a signed
object that proves a Work Product Provenance object ({{provenance}})
describes one specific artifact and was attached by a trusted mediator,
without making that provenance object authority-bearing. The binding is
a distinct object beside the provenance object. It adds no member to the
provenance object and does not modify it: that object still carries only
the five members {{provenance}} defines. The binding names the
provenance object and the artifact by digest, so binding one to the
other changes neither.

The binding is OPTIONAL. Its absence means only that attribution
integrity is unproven for an artifact; absence is never a signal that
authority is present, nor that it is denied. What a reader may do remains
the Receiving Mission's Authority Set to decide ({{handoff}}).

## Conceptual Model {#binding-model}

The binding profiles the subject, digest, and predicate model of
software supply-chain attestation, in-toto {{IN-TOTO}} and SLSA
{{SLSA}}, without adopting its serialization. The artifact is the
subject, named by a content digest; the sealed provenance object is the
predicate, named by its own digest and carried alongside; the trusted
mediator is the attester. The envelope is the family's own JWS Compact
Serialization {{RFC7515}} idiom, the same signed-JWT form the suite uses
for signed Security Event Tokens and issuer-signed Mission records,
rather than a supply-chain attestation format. A future translation shim
that emits a byte-compatible in-toto or SLSA attestation for
supply-chain tooling is possible but out of scope here
({{binding-scope}}).

## The Binding Object {#binding-object}

A Work Product Binding is a JWT {{RFC7519}} in JWS Compact Serialization
{{RFC7515}}, signed by the trusted mediator that attached the provenance
object, an Agent Deployment's execution environment (`harness`) or the
Mission Issuer (`issuer`; {{provenance}}), with that mediator's own
signing key. The producing agent MUST NOT sign it: a binding
an agent signs over its own work is the same self-authored,
authority-bearing forgery the custody boundary of {{provenance}}
prevents.

The protected header carries:

typ:
: REQUIRED. `mission-work-product-binding+jwt`. Per {{RFC7515}}
  Section 4.1.9 the value omits the `application/` prefix of the media
  type registered in {{iana}}. The distinct `typ` domain-separates the
  binding so a binding digest can never be read as an authority
  artifact.

alg:
: REQUIRED. An asymmetric JWS algorithm. `none` MUST NOT be used.

kid:
: REQUIRED. A key identifier that selects the signing mediator's key
  within the deployment's published key set. A relying party resolves it
  by the mediator's `role`, reusing the family's existing role-keyed
  resolution path ({{I-D.draft-mcguinness-mission-audit}}): the Mission
  Issuer key through the Authorization Server metadata `jwks_uri` when
  `role` is `issuer`, and the harness signing key published in the
  deployment key set when `role` is `harness`. This document defines no
  new key-resolution path.

The JWS payload is a JSON object {{RFC8259}} carrying:

iss:
: REQUIRED. The Mission Issuer or deployment URL under which the key set
  that publishes the signing mediator's key is discoverable. It is the
  stable, discoverable identifier of that published key material, not the
  mediator's own `id`. It binds the object to that deployment and is the
  `iss` used when recomputing `provenance_digest` below, so that digest
  reproduces from the recorded object.

mediator:
: REQUIRED. The trusted mediator that attached the provenance object and
  signed this binding, as the `id` and `role` of the attacher of
  {{provenance}}, `role` being `harness` (the Agent Deployment's
  execution environment) or `issuer` (the Mission Issuer). `mediator.id`
  MUST differ from the provenance object's `producer`; a binding whose
  mediator names the producing agent is that agent self-attaching under
  another name.

artifact_digest:
: REQUIRED. The subject. `sha-256:` followed by the unpadded base64url
  encoding of the SHA-256 {{RFC6234}} digest of the artifact's octets.
  The octets are those the artifact is actually exchanged as: a file, a
  message, a memory entry, a queue event, or any other opaque content.
  How an artifact is serialized to those octets is the producer's
  concern; this document defines no artifact serialization and does not
  canonicalize the artifact. The producer and consumer MUST agree on the
  exact bytes so that both compute the same digest.

provenance_digest:
: REQUIRED. The predicate anchor. It binds the sealed provenance object
  without modifying it. Compute it with the integrity-anchor
  construction of {{I-D.draft-mcguinness-oauth-mission}}: build the
  envelope

  ~~~
  {
    "typ": "mission-work-product-provenance",
    "iss": "<the binding's iss>",
    "value": <the five-member provenance object>
  }
  ~~~

  where `value` is the provenance object of {{provenance}} unchanged;
  canonicalize the envelope with JCS {{RFC8785}}; compute SHA-256
  {{RFC6234}} over the canonical bytes; and encode as `sha-256:`
  followed by the unpadded base64url of the digest.
  `mission-work-product-provenance` is a committed-object `typ` this
  document defines under the collision-resistant-name rule of
  {{I-D.draft-mcguinness-oauth-mission}}; that document defines no
  registry of such values and none is registered here.

The binding MAY carry other standard JWT {{RFC7519}} claims, such as
`iat`; they do not affect either digest.

## Verification {#binding-verification}

A receiver that holds the artifact, the five-member provenance object,
and the binding verifies in this order:

1. Reject the binding unless its protected `typ` is
   `mission-work-product-binding+jwt`.
2. Resolve the `kid` in the key set discoverable at the binding's `iss`,
   by the `mediator.role` as above, and verify the JWS signature. Reject
   a binding signed with `none` or with a symmetric algorithm.
3. Confirm the signer is a trusted mediator for this type: the
   `mediator` member MUST correspond to the key that produced the
   signature, its `role` MUST be `harness` or `issuer`, and
   `mediator.id` MUST differ from the provenance object's `producer`.
   Reject on any mismatch.
4. Recompute `artifact_digest` over the received artifact octets and
   reject unless it matches. A receiver MUST reject an `artifact_digest`
   whose algorithm prefix it does not recognize and MUST NOT treat an
   unrecognized prefix as `sha-256`.
5. Recompute `provenance_digest` over the JCS envelope of the received
   provenance object as above, using the binding's `iss`, and reject
   unless it matches. Apply the same unrecognized-prefix rule.
6. A binding that verifies proves attribution integrity only. The
   Receiving Mission MUST STILL re-evaluate any proposed action under
   its own Authority Set ({{handoff}}) before acting. A verified binding
   is a precondition to trusting the attribution, never an input to a
   permit decision.

Steps 4 and 5 together bind the attribution to the artifact: the
artifact is fixed by `artifact_digest`, and the provenance object
describing it is fixed by `provenance_digest`, so under the mediator's
signature neither can be substituted for the other.

## Guardrails {#binding-guardrails}

- The binding proves attribution integrity, never authority. A content
  digest narrows what a provenance object can be re-attached to; it does
  not widen what a reader may do. The invariant of {{invariant}}, that
  information may propagate and authority may not, is unchanged: a
  verified binding is still gated by the Receiving Mission's Authority
  Set ({{handoff}}) and is never a permit input.
- The `typ` domain separation of {{binding-object}} keeps a binding
  digest from ever being mistaken for an authority artifact.
- The residual and out-of-scope items of {{security-considerations}}
  are unchanged. A binding fixes one artifact to one provenance object;
  it does not bound the emergent-authority-through-coordination
  aggregate, and it neither quarantines a work product nor blocks its
  consumers.

## Out of Scope {#binding-scope}

This document binds one artifact to one sealed provenance object and
stops there. The following are deliberately deferred:

- A verifiable lineage chain, making `parent_artifact` ({{provenance}})
  a digest so a provenance chain is itself tamper-evident, is a further
  change to the sealed object and is left to a later pass.
- A native in-toto or SLSA attestation output, a byte-compatible
  translation shim for supply-chain tooling, is future interoperability
  work; this document defines only the family's JWS binding.

# Conformance {#conformance}

This section maps the invariant of {{invariant}} and the handoff rule
of {{handoff}} to per-role requirements, so a deployment claiming this
document is testable against them.

A mediator that attaches Work Product Provenance (an Agent Deployment's
execution environment, or the Mission Issuer) MUST:

- populate `mission_id`, `deployment_id`, and `producer` from its own
  record of the Mission and Agent Deployment executing when the
  artifact was produced, never from an unauthenticated assertion by
  the producing agent ({{provenance}});
- carry no member beyond the five this document defines, and no
  authority, constraint, classification, or permission in any of them
  ({{provenance}}); and
- disclose an attached object under the same access rules as the
  deployment's other Mission evidence ({{provenance}}).

A producing agent MUST NOT self-author or self-assert its own Work
Product Provenance ({{provenance}}).

A Receiving Mission (its agent, harness, or PDP) MUST:

- re-evaluate any proposed action against its own Authority Set before
  acting on a work product or the provenance attributed to it,
  regardless of the Producing Mission's approval or lifecycle state
  ({{handoff}}); and
- treat a Work Product Provenance object, or its absence, as
  attribution only, and MUST NOT treat either as authority for an
  action ({{invariant}}, {{handoff}}).

Any party needing authority over a work product's subject matter MUST
obtain it through the authority plane, a Child Mission request or
another authorized Mission transition, and MUST NOT derive it from a
work product or its provenance ({{handoff}}).

# Security Considerations {#security-considerations}

The invariant of {{invariant}} is the security property this document
provides: authority never rides a work product. The provenance object
carries no authority by construction, and the handoff rule denies any
transfer of the Producing Mission's authority through copying,
referencing, embedding, or communicating an artifact. An agent that
reads a work product and proposes an action is gated by the Receiving
Mission's own Authority Set, so a work product cannot be used as a
capability.

One residual is not closed by this document. Independent Missions,
each acting within its own bounds, can communicate through shared state
so that discoveries, credentials, techniques, or intermediate results
persist across runtimes and Missions, and individually acceptable
actions compose into behavior no single Mission authorized. The handoff
rule prevents any one artifact from conferring authority; it does not by
itself bound this aggregate composition through an unmanaged carrier.
The security model records this as the emergent-authority-through-
coordination threat
({{I-D.draft-mcguinness-mission-security-model}}).

Bounding that aggregate is anticipated defense-in-depth, deferred to
later companions and not specified here: an issuer-assigned or
deployment-assigned classification of a shared-state effect; a
communications and audience envelope for what an agent may write and who
may read it; lineage-keyed aggregate bounds across a provenance chain;
and quarantine of a work product with blocking of its consumers when the
Producing Mission is compromised. This document specifies none of them
now.

# Privacy Considerations {#privacy-considerations}

Work Product Provenance attributes an artifact to a Mission and to a
producing principal, so it can reveal the existence of a Mission and the
identity of an actor to anyone who reads the artifact. A deployment
attaches provenance only where attribution is warranted, keeps it to
the five members this document defines, and discloses it under the same
access rules as its other Mission evidence. The object is policy-free,
so it never carries authority, constraint, or classification that could
widen what a reader learns. This document adds no anonymous surface.

# IANA Considerations {#iana}

## Media Type Registration

IANA is requested to register one media type per {{RFC6838}}.

### application/mission-work-product-binding+jwt

- Type name: application
- Subtype name: mission-work-product-binding+jwt
- Required parameters: none
- Optional parameters: none
- Encoding considerations: binary; JWS Compact Serialization
- Security considerations: see {{security-considerations}} and
  {{binding-guardrails}}
- Interoperability considerations: see this document
- Published specification: this document
- Applications that use this media type: Mission-Bound Authorization
  deployments that bind Work Product Provenance to an artifact
- Fragment identifier considerations: not applicable
- Additional information:
  - Deprecated alias names for this type: none
  - Magic number(s): none
  - File extension(s): none
  - Macintosh file type code(s): none
- Person & email address to contact for further information:
  Karl McGuinness <public@karlmcguinness.com>
- Intended usage: COMMON
- Restrictions on usage: none
- Author: IETF
- Change controller: IETF

The committed-object `typ` value `mission-work-product-provenance` used
to compute `provenance_digest` ({{binding-object}}) is not registered:
the core specification defines no registry of such values and relies on
the collision-resistant-name rule ({{I-D.draft-mcguinness-oauth-mission}}).
This document adds the informative in-toto {{IN-TOTO}} and SLSA {{SLSA}}
references as the conceptual model for {{binding}}.

# Acknowledgments
{:numbered="false"}

This document is part of the Mission-Bound Authorization for OAuth 2.0
set and defines the artifact-plane complement to the credential-plane
invariants: information may propagate, and authority may not.

--- back
