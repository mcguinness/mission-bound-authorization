---
title: "Mission Evidence Envelope"
abbrev: "Mission Evidence Envelope"
category: exp

docname: draft-mcguinness-mission-evidence-envelope-latest
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
 - evidence
 - registry
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-evidence-envelope.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC3339:
  RFC6234:
  RFC6838:
  RFC7493:
  RFC7515:
  RFC7518:
  RFC7519:
  RFC7800:
  RFC8126:
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
  I-D.draft-mcguinness-mission-substrate:
    title: "Mission Substrate Requirements"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-substrate.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

informative:
  I-D.draft-mcguinness-mission-mandate:
    title: "Mission Mandate"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-mandate.html
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
  I-D.draft-mcguinness-mission-runtime-evidence:
    title: "Mission Runtime Evidence"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-runtime-evidence.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-consent-evidence:
    title: "Mission Consent Evidence"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-consent-evidence.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

--- abstract

The family defines roughly thirty `application/mission-*` evidence
media types, each repeating the same handful of members (a type
discriminator, a record identifier, a Mission reference, an emitter,
a timestamp, an integrity envelope) beside its own payload-specific
content. This document defines a generic, binding-neutral **Mission
Evidence Envelope** and a **Mission Evidence Payload Type Registry**
that a future evidence kind MAY register into instead of minting
another one-off object and another media type, without weakening the
per-kind schema and verification separation the family already
depends on. It defines one pilot payload type, **Intent Admission
Evidence**, the first consumer of the OAuth binding's Intent
Submission Evidence dispatch. This document does not migrate any of
the family's existing evidence kinds onto the envelope; whether an
existing kind migrates is that kind's own specification's decision,
addressed here only as a non-normative migration plan.

--- middle

# Introduction

Consent Evidence, Decision Evidence, Execution Evidence, Refusal
Records, the Mission Receipt, Approval Governance, Harness Evidence,
Egress Evidence, Containment Evidence, the Protected Event Receipt,
Child Evidence, Discovery Evidence, the Work Product Binding, and the
audit profile's own approval, lifecycle-transition, derivation, and
erasure records are each a closed JSON object with its own media
type, its own integrity envelope, and its own retention rule. Read
across the family, they share a shape: something that identifies what
kind of record this is, a record identifier, a reference to the
Mission the record concerns, the identity of the component that
produced it, a timestamp, and an integrity envelope around
kind-specific content. A 2026-08-24 architecture-shape review counted
twenty-nine registered media types built on that repeated shape and
recommended one generic envelope, a registered payload-type registry
with closed schemas per type, and specialized cryptographic containers
preserved only where they buy a genuinely different property.

This document answers that recommendation with a mechanism and one
pilot consumer, not with a retroactive claim on the family's existing
records. It defines:

* the **Mission Evidence Envelope** ({{mission-evidence-envelope}}):
  the generic wrapper (`type`, `id`, `mission`, `emitter`,
  `occurred_at`, `sequence`, `related`, `payload`, and an integrity
  envelope);
* the **Mission Evidence Payload Type Registry**
  ({{evidence-payload-type-registry}}): registration rules requiring a
  closed payload schema, a verification procedure that establishes
  producer authorization and not merely signature validity
  ({{producer-authorization}}), and a named producer, so a shared
  envelope and a shared media type never relocate domain separation
  into a payload member; and
* **Intent Admission Evidence** ({{intent-admission-evidence}}): the
  registry's first registered payload type and the first consumer of
  the OAuth binding's Intent Submission Evidence dispatch, which
  shipped with an empty type registry that refuses every presented
  entry until a profile registers one.

This document does not migrate Decision Evidence, Execution Evidence,
Refusal Records, the Mission Receipt, Consent Evidence, Approval
Governance, or any other existing evidence kind onto this envelope.
Each of those objects keeps its own members, its own media type, and
its own integrity envelope exactly as its defining specification fixes
them. Whether a given kind migrates onto this envelope in the future
is a decision for that kind's own specification, made on its own
merits and its own breaking-change and deprecation terms; this
document states only a non-normative migration plan
({{migration-plan}}) and does not require, schedule, or presume any
particular migration. A reader should not infer, from this document's
existence, that an existing evidence kind's current media type is
deprecated: it is not, unless and until that kind's own specification
says so.

# Status: An Optional, Experimental Mechanism {#doc-status}

<!-- family-status: BEGIN (generated from family-manifest.json; exact-matched by scripts/check-family-manifest.mjs) -->
Role: companion. Spec maturity: sketch. Maintenance: lab-best-effort.
Implementation: 23 conformance rows in conformance-manifest.json (23 todo).
Adopt when: A new evidence kind is being designed and a deployment wants to avoid minting another bespoke media type, or Intent Admission Evidence's inbound assertion and emitted attestation are needed.
Requires: nothing beyond its listed references.
<!-- family-status: END -->

This document is Experimental. It has no known implementation, no
migrated evidence kind, and no adopter commitment on record. A
deployment MAY implement the envelope and the Intent Admission payload
type independently of every other family document; adopting it
creates no dependency on Mission-Bound Runtime Enforcement, its
AuthZEN binding, or their evidence companion
({{I-D.draft-mcguinness-mission-runtime-evidence}}), because none of
this document's normative content depends on records those documents
define.

# Conventions and Terminology {#conventions-and-definitions}

{::boilerplate bcp14}

**Envelope instance**: a JSON object conforming to
{{mission-evidence-envelope-members}}, identified by its `type`
member.

**Payload type**: a registration in the Mission Evidence Payload Type
Registry ({{evidence-payload-type-registry}}) fixing one `type`
value's closed `payload` schema, verification procedure, and producer.

**Producer**: the component authorized, under a payload type's
verification procedure, to emit an envelope instance of that type for
a named Mission.

# Mission Substrate {#mission-substrate}

This document is defined against the Mission model rather than
against OAuth 2.0 mechanics: it is a substrate-neutral consumer, and
this section is its consumption declaration under the rule of Mission
Substrate Requirements ({{I-D.draft-mcguinness-mission-substrate}})
that a substrate-neutral profile declare the kernel functions and
optional capabilities it consumes.

It is a kernel-only consumer. From the contextual-governance kernel it
consumes the Mission identifier and issuer, carried in every envelope
instance's `mission` object. Its instances are not the kernel's
ordered governance record; they are a separate, joinable evidence
stream, retained no shorter than the Mission's audit horizon
({{mission-evidence-envelope-retention}}).

Its declaration against the optional capabilities:

| Capability | Consumption | Scope of consumption |
| --- | --- | --- |
| Structured Authority | not consumed | No envelope instance this document defines represents or evaluates machine-actionable authority |
| Lifecycle-Gated Authorization | not consumed | This document records evidence; it neither gates nor grants authority |
| State-Observable | not consumed | No instance establishes or consults Mission state |
| Monotonic Derivation | not consumed | No instance derives or narrows authority |
| Credential-Bound | not consumed | The Mission enters an instance only as the `mission` reference object; this document verifies no credential binding beyond {{producer-authorization}} |
| Authorized Context Correlation | not consumed | No instance correlates against an authorized context beyond the Mission reference |
| Independently Verifiable | not consumed | Not consumed, and supplied in scoped form: a verifier holding the producing authority's published keys and the producer-authorization rule of {{producer-authorization}} verifies an instance independently of the emitting deployment; this document defines no transparency-service registration itself |
| Portable Evidence | not consumed | Portability beyond a party holding the relevant issuer's published keys requires the transparency mechanisms of the audit profile ({{I-D.draft-mcguinness-mission-audit}}), where a deployment adopts them |
{: title="Mission Evidence Envelope capability consumption"}

# Mission Evidence Envelope {#mission-evidence-envelope}

A Mission Evidence Envelope instance is a JSON object with the members
below. A registered payload type ({{evidence-payload-type-registry}})
fixes the content of `payload` alone; every other member is fixed by
this document and is identical across every payload type.

## Envelope Members {#mission-evidence-envelope-members}

`type`:
: REQUIRED. A string. The registered payload type
  ({{evidence-payload-type-registry}}): the schema `payload` is closed
  to, and the verification procedure a consumer applies to the whole
  instance.

`id`:
: REQUIRED. A string. A unique identifier for this envelope instance.
  ABNF: `1*64( ALPHA / DIGIT / "-" / "_" )`. At least 128 bits of
  entropy.

`mission`:
: REQUIRED. An object with `id` and `issuer`: the Mission this
  instance concerns.

`emitter`:
: REQUIRED. An object with `id` (REQUIRED, a string identifying the
  emitting component) and `role` (REQUIRED, a string). This document
  defines one role, `issuer`: the Mission issuer identified by
  `mission.issuer`, or a component the issuer specifically registers
  to emit on its behalf ({{producer-authorization}}). A payload type
  registration MAY require additional roles, coordinated the same way
  a `type` value is (collision-resistant, registered alongside the
  type). `emitter` alone is a claim, not a proof of authorization;
  {{producer-authorization}} fixes what a verifier additionally checks.

`occurred_at`:
: REQUIRED. An RFC 3339 {{RFC3339}} timestamp of the event this
  instance records.

`sequence`:
: REQUIRED. An integer, zero or greater. A per-(Mission, emitter)
  monotonically increasing sequence indicator: a verifier detects
  gaps and orders instances within (Mission, emitter). It does not by
  itself establish Mission-wide order across distinct emitters.

`related`:
: OPTIONAL. An array, default empty. Each entry is an object with
  `relation` (REQUIRED, a collision-resistant name, the same guidance
  as a `typ` value, {{I-D.draft-mcguinness-oauth-mission}}) and
  `reference` (REQUIRED, a string, the correlated identifier). A
  registered payload type MAY require specific `relation` values; this
  document requires none.

`payload`:
: REQUIRED. An object. Content fixed exclusively by the registered
  `type`'s closed schema ({{evidence-payload-type-registry}}). This
  document defines no members of its own on `payload`.

`evidence_envelope`:
: REQUIRED. An object, the integrity protection
  ({{mission-evidence-envelope-integrity}}), carrying `format` (string,
  required) and `value` (string, required).

A Mission Evidence Envelope instance is closed to uncoordinated
extension at this top level: a member outside this list is not part
of this document's schema, and a registered payload type extends the
object only through `payload`.

## Payload Type Registry {#evidence-payload-type-registry}

`type` selects a registration, and a registration fixes exactly four
things: the closed schema `payload` carries; the verification
procedure a consumer applies to the whole instance, which MUST
establish producer authorization under {{producer-authorization}} and
not only that the envelope integrity check of
{{mission-evidence-envelope-integrity}} passes; the producer or
producer class, and the `emitter.role` values, authorized to emit it;
and its registered `type` string.

A verifier MUST reject an instance whose `type` it does not recognize,
and MUST NOT interpret `payload` under any schema other than the one
the recognized `type` registers; an unrecognized `type` is refused,
never processed under a guessed or default schema. This is the same
reject-never-guess discipline the Mission Intent Submission envelope's
evidence dispatch already applies to its own `type` member
({{I-D.draft-mcguinness-oauth-mission}}).

Registration requires: a collision-resistant name for `type`, under
the same guidance as an integrity-anchor `typ` value
({{I-D.draft-mcguinness-oauth-mission}}); a stable reference defining
the closed `payload` schema; a stable reference defining the
verification procedure, including the producer-authorization check
{{producer-authorization}} requires; and the producer or producer
class, and permitted `emitter.role` values, authoritative for
instances of that type. The registration mechanics and Designated
Expert criteria are in {{iana}}.

**Registration is not frozen for its full lifetime.** A registered
type's change controller MAY publish a compatible update to its
schema or verification procedure under the same `type` value: a
clarification that does not change which bytes conform, or a
security-hardening amendment that narrows what a verifier accepts
without admitting anything a prior conforming verifier would have
rejected, is a same-`type` revision, subject to the change
controller's own review and a preserved change history a verifier can
consult. A `type` value is retired and a new one registered only when
a change would accept or require content an existing conforming
instance does not carry, or would reinterpret an existing member's
meaning: an incompatible schema change or a semantic reinterpretation.
This mirrors ordinary IANA registry update practice (compatible
erratum and security-update paths exist alongside the closed-question
of what counts as a new registration) rather than treating every
change as equivalent to inventing a new artifact. This document seeds
the registry with one payload type, `mission-intent-admission`
({{intent-admission-payload-type}}).

## Domain Separation {#mission-evidence-envelope-domain-separation}

Sharing one envelope shape and one media type across every registered
payload type does not relocate domain separation into a payload
member the way a single flat `typ` value list would. Four things hold
it in place instead. First, `type` is itself inside the bytes the
`evidence_envelope` signs
({{mission-evidence-envelope-integrity}}): a party that relabels
`type` without the signer's key breaks the signature, so `type` is
tamper-evident, not an unauthenticated routing hint read before
verification. Second, a verifier applies a payload's schema and
verification procedure only after resolving `type` to exactly one
registration ({{evidence-payload-type-registry}}); there is no shared,
generic parse of `payload` a verifier could apply across types. Third,
a schema or procedure change that would accept or require different
conforming bytes is a new `type`, never a silent reinterpretation of
an existing one, while a compatible clarification or hardening stays
reviewable against its change history
({{evidence-payload-type-registry}}). Fourth, a valid signature and a
schema-conformant payload are necessary but not sufficient: a verifier
additionally checks that the signing emitter is authorized to speak
for the named Mission and type ({{producer-authorization}}), so domain
separation is never reduced to "the bytes parse and the signature
verifies."

This is a narrower and safer construction than the single universal
`typ` list this family previously declined: no payload member ever
carries domain separation, `type` is bound by the signature rather
than trusted as presented, every type keeps its own closed schema and
verification procedure, and no signature alone establishes producer
authority. It does not touch the media-type domain separation the
family's existing evidence objects already carry under their own,
separately registered media types
({{I-D.draft-mcguinness-mission-runtime-evidence}},
{{I-D.draft-mcguinness-oauth-mission-consent-evidence}}); this
document neither re-registers them nor requires that they migrate.

## Producer Authorization {#producer-authorization}

The generic envelope integrity check
({{mission-evidence-envelope-integrity}}) proves that the exact bytes
of an instance, `evidence_envelope` excluded, are signed by whatever
key the JWS `kid` resolves to. It does not by itself prove that the
resolved key's owner is entitled to speak for the named
`mission.issuer`, `mission.id`, and `type`: any component with a
resolvable signing key can construct a well-formed, correctly signed,
schema-conformant instance naming a Mission it has no relationship to,
unless something additionally checks that binding.

A payload type's verification procedure is therefore incomplete, and
non-conforming to this registry, unless it establishes all of the
following before an instance is treated as verified:

1. which `emitter.role` value(s) the type permits, and that the
   instance's `emitter.role` is one of them;
2. how a verifier determines the canonical identity authorized to hold
   that role for the named `mission.issuer` (the issuer identity
   itself, or a component the issuer specifically registers, never a
   value the instance merely asserts about itself); and
3. that the JWS signing key is one that canonical authority has
   published, or specifically authorized, for this evidence usage,
   not merely a key that is resolvable somewhere.

A verifier MUST reject an instance failing any of these checks,
treating the failure identically to a signature or schema failure: an
otherwise well-formed, correctly signed, schema-conformant instance
naming a Mission or producer role it is not authorized for is not
verified evidence.

## Integrity {#mission-evidence-envelope-integrity}

Every committed or signed JSON value in this document satisfies the
canonicalization, I-JSON conformance, and algorithm-agility rules of
the Mission Substrate's Default Commitment Construction
({{I-D.draft-mcguinness-mission-substrate}}): JCS {{RFC8785}}
canonicalization, parse-time duplicate-member-name rejection, the
I-JSON {{RFC7493}} numeric and string domain, and the reject-unknown,
no-downgrade rule for any algorithm prefix. This document does not
restate those rules; it instantiates them.

A Mission Evidence Envelope instance's integrity protection is a JWS
Compact Serialization {{RFC7515}} (`format` `jws-compact`, the only
format this document defines) whose payload is the JCS canonical
bytes of the instance with the `evidence_envelope` member removed. A
verifier MUST perform the following steps, in order, and MUST NOT
treat an instance as verified if any step fails:

1. Decode the JWS payload.
2. Compute the JCS canonical bytes of the outer instance with the
   `evidence_envelope` member removed.
3. Require byte-for-byte equality between the decoded payload of step
   1 and the canonical bytes of step 2, rejecting the instance on any
   difference.
4. Verify the JWS signature and protected header against the
   candidate emitter's published or registered signing key.
5. Apply {{producer-authorization}}: reject unless the signing key,
   `emitter`, `mission.issuer`, and `type` are mutually authorized
   under the recognized type's registration.

The JWS protected header MUST carry `kid` (a key identifier resolvable
under {{producer-authorization}}), `alg` (`ES256` {{RFC7518}}
mandatory to implement; an implementation MAY offer other JOSE
algorithms but MUST implement `ES256`, and MUST reject `none` and any
protected header whose `alg` does not match the algorithm family of
the resolved key), `typ` (`application/mission-evidence+jws`, the one
value for every payload type this envelope secures, {{iana}}), and
`cty` (`application/mission-evidence+json`, the one media type every
instance of this envelope carries regardless of `type`, {{iana}}). A
verifier MUST reject a JWS whose protected `typ` or `cty` does not
match these exact values.

Where the selected signing key is identified as compromised by the
deployment-defined key-status mechanism, a verifier MUST require an
independently trusted existence proof over the complete signed
instance, or its unambiguous typed digest, establishing existence
before the compromise boundary, before continuing verification; the
instance's own asserted timestamps never satisfy this.

## Retention {#mission-evidence-envelope-retention}

A Mission Evidence Envelope instance MUST be retained for at least the
deployment's audit retention window, no shorter than the Mission's
audit horizon ({{I-D.draft-mcguinness-oauth-mission}}). This duty
falls on the producer at the moment of emission; the producer
discharges it either by retaining the instance itself, or by
delivering it to an evidence store or collector the deployment
designates for this purpose, whose successful acknowledgment of
receipt discharges the producer's own retention obligation. A
producer that ceases to hold an instance after a successfully
acknowledged delivery to such a collector is not, for that reason
alone, non-conforming; the collector then carries the retention
window. A registered payload type MAY require stricter retention,
different acknowledgment semantics, or a specific durable store where
its own governance requirements differ from this default.

## Specialized Containers {#specialized-evidence-containers}

Not every committed artifact belongs inside this envelope's generic
`payload` wrapping. An SD-JWT Mandate
({{I-D.draft-mcguinness-mission-mandate}}) is a portable, selectively
disclosable claim set whose wire form is the SD-JWT's own compact
serialization; wrapping it in a JSON `payload` member would require
re-encoding the disclosures or losing selective disclosure entirely. A
SCITT Signed Statement and Receipt
({{I-D.draft-mcguinness-mission-audit}}) commit a payload-preimage
digest at a transparency boundary under COSE, a distinct signing stack
and trust model from this envelope's JOSE `evidence_envelope`, and
registering a Receipt as a payload type here would confuse a
transparency-service commitment with a producer-signed evidence
record. Both stay in their own compact, natively typed wire forms,
outside this registry.

## Migration Plan (Non-Normative) {#migration-plan}

This document requires no existing evidence kind to migrate, and
claims no timeline for one doing so. This section is a non-normative
inventory for whichever kind's own editors choose to evaluate it, so
this registry does not become, in the review's words, "a permanent
parallel envelope instead of consolidation" by default.

Candidates fall into three tiers, ordered by how disruptive adopting
this envelope would be to what already ships:

1. **Unregistered or locally-agreed kinds with no pinned wire vector**:
   Orchestration Evidence (`mission-orchestration-evidence`, a
   local-use identifier with no registered media type,
   {{I-D.draft-mcguinness-oauth-mission}} evidence-types catalog
   discussion) and Shaping Evidence (no fixed schema or media type
   today). Registering either as a payload type here, instead of
   minting its own bespoke media type, costs nothing a deployment has
   already pinned; this is the tier where adopting the registry is
   cheapest and where a first real migration, if one lands, should
   start.
2. **Registered-but-unsigned kinds**: Harness Evidence and Egress
   Evidence fix an operational `typ` of `none` today. Adding an
   envelope-based signed form is additive (a new option beside the
   existing unsigned form), not a breaking change to either.
3. **Heavily pinned, tested kinds**: Decision Evidence, Execution
   Evidence, Refusal Records, the Mission Receipt, Consent Evidence,
   and Approval Governance each carry worked test vectors and
   conformance-manifest coverage keyed to their current media types.
   Moving any of these is a breaking change to pinned vectors and
   requires that kind's own dedicated migration and deprecation plan,
   never a unilateral decision by this document.

Landing an actual migration is deliberately out of this document's own
scope; it is flagged here as a candidate follow-on for the affected
kind's own editors to schedule.

# Intent Admission Evidence {#intent-admission-evidence}

Intent Admission Evidence spans two planes, and the terms below keep
them distinct because the AS's own evidence hook does
({{I-D.draft-mcguinness-oauth-mission}}). Inbound, a client presents an
**Intent Admission Assertion** as an Intent Submission Evidence entry
({{intent-admission-assertion}}): this is the first type this document
series registers under the Mission Intent Submission envelope's
evidence dispatch, which shipped with an empty type registry and
refuses every presented entry until a profile registers one. Emitted,
the AS records its own admission attestation as a **Mission Intent
Admission** payload type of the Mission Evidence Envelope
({{intent-admission-payload-type}}): the first payload type this
document's registry seeds ({{evidence-payload-type-registry}}). The
inbound assertion is client-presented policy input; the emitted record
is the issuer's own signed attestation, not independent proof of the
inbound assertion ({{intent-admission-payload-type}}). Neither is
authority: verified evidence remains authenticated input to AS policy,
never a copied entry in the Authority Set and never the Mission
approval event ({{I-D.draft-mcguinness-oauth-mission}}).

## The Intent Admission Assertion {#intent-admission-assertion}

The evidence entry's `type` is `mission-intent-admission-assertion`.
The entry is closed to exactly two members:

`type`:
: REQUIRED. The string `mission-intent-admission-assertion`.

`assertion`:
: REQUIRED. A string, a JWS Compact Serialization {{RFC7515}}: the
  Intent Admission Assertion.

The assertion's JOSE protected header MUST carry `typ`
`mission-intent-admission-assertion+jws`, a collision-resistant value
distinct from every other JWS this family defines, so an assertion of
this exact type cannot be substituted for, or accepted in place of, a
JWS from a different profile that happens to share a key. This `typ`
value is not separately registered as an IANA media type: it names a
JOSE object identity, never transmitted as a `Content-Type`, and this
document mints no bespoke media type for the assertion.

The protected header MUST also carry `alg` (`ES256` {{RFC7518}}
mandatory to implement; an implementation MAY offer other JOSE
algorithms but MUST implement `ES256`) and `kid` (a key identifier
resolvable as described below). A verifier MUST reject an assertion
whose `alg` is `none`, whose `alg` does not match the algorithm family
of the key `kid` resolves to, or whose protected `typ` is not exactly
`mission-intent-admission-assertion+jws`.

The admission issuer's key used to sign this assertion MUST be
published or configured specifically for Intent Admission Assertion
signing, distinct from any other key-use the admission issuer
publishes (for example, a `use` or `key_ops` scoping, or a
deployment-published key-purpose registration naming this exact
usage). A verifier MUST reject an assertion signed by a key that is
resolvable but not scoped to this usage; a multipurpose signing key
with no usage scoping does not satisfy this requirement.

The decoded assertion's claims are closed to exactly these members:

`iss`:
: REQUIRED. A string. The admission issuer: the party attesting to
  the Intent's originator and the admission decision, distinct from
  the Mission AS.

`aud`:
: REQUIRED. A string. The Mission AS's issuer identifier.

`iat`, `exp`:
: REQUIRED. RFC 3339-equivalent JWT numeric dates {{RFC7519}}, the
  assertion's validity window.

`jti`:
: REQUIRED. A string. The assertion identifier, unique within the
  admission issuer's namespace.

`intent_hash`:
: REQUIRED. A string. The exact `intent_hash` this assertion applies
  to ({{I-D.draft-mcguinness-oauth-mission}}).

`originator`:
: REQUIRED. An object with `iss` and `sub`. Who the admission issuer
  attests originated the Intent, distinct from the presenter below.

`presenter`:
: REQUIRED. An object with `client_id` (REQUIRED, a string) and `cnf`
  (OPTIONAL, a confirmation-method object {{RFC7800}}), the party this
  assertion authorizes to submit the Intent.

`admission_basis`:
: REQUIRED. An object with `type` (REQUIRED, a string, a
  collision-resistant name for the upstream decision class) and
  `reference` (REQUIRED, a string, an admission-issuer-scoped pointer
  to that decision). This document does not standardize the upstream
  admission or consent system `reference` points into.

`status`:
: REQUIRED. A string. `active` is the only value this document
  defines; a verifier MUST treat any other value as not verified.
  `status` reflects the admission issuer's state at the instant it
  signed the assertion; it is not re-checked afterward
  ({{intent-admission-security}}).

## Verification Procedure {#intent-admission-verification}

Beyond the Mission Intent Submission envelope's own dispatch rules
({{I-D.draft-mcguinness-oauth-mission}}), the AS verifies an entry of
this type as follows, rejecting the submission with
`invalid_mission_intent_evidence` on any failure:

1. Confirm the entry carries exactly `type` and `assertion`.
2. Decode `assertion` as a JWS Compact Serialization. Confirm the
   protected `typ` is exactly `mission-intent-admission-assertion+jws`
   and `alg` is not `none`.
3. Resolve `kid` in the admission issuer's key material scoped
   specifically to Intent Admission Assertion signing, established by
   deployment configuration (an issuer allowlist, a configured JWKS
   with usage scoping, or equivalent); this document does not
   standardize admission-issuer discovery. Confirm `alg` matches the
   resolved key's algorithm family.
4. Verify the JWS signature.
5. Verify `aud` equals this AS's issuer identifier.
6. Verify the current time is within `iat` and `exp`, under the
   deployment's clock-skew tolerance.
7. **Atomically reserve `jti`**: the AS MUST use an atomic
   compare-and-set (or equivalent single-writer-wins primitive)
   against a store keyed by (admission issuer, `jti`), succeeding only
   if no prior submission has reserved or committed that key within
   its validity window. A concurrent submission that loses the race
   observes reservation failure and MUST be refused as replay; it
   MUST NOT proceed to verify the same assertion a second time in
   parallel. A reservation that is not later committed (step 10) MUST
   be released no later than `exp`, freeing the identifier for a
   legitimate retry; a committed reservation is permanent for the
   window this AS retains submission records.
8. Verify `intent_hash` equals the provisional `intent_hash` computed
   at submission-processing step 3
   ({{I-D.draft-mcguinness-oauth-mission}}).
9. Verify `presenter.client_id`, and `cnf` where present, equal the
   presenter the containing exchange established; the assertion is
   never an alternative client-authentication mechanism and never
   selects the presenter ({{I-D.draft-mcguinness-oauth-mission}}).
10. Verify `status` is exactly `active`. On success, **commit** the
    `jti` reservation of step 7 (permanent, see above). On failure at
    this step or any of steps 2-9, **release** the reservation.

This type defines no evidence-lineage exception: a shaping or approval
revision that changes `intent_hash` requires a fresh assertion with a
fresh `jti`, under the general rule of
{{I-D.draft-mcguinness-oauth-mission}}.

**Composition with creation-fingerprint idempotent recovery.** On a
surface that also carries a Mission-creation idempotency fingerprint
(expansion, child creation, {{I-D.draft-mcguinness-oauth-mission}}),
this `jti` reservation is a distinct, submission-plane replay control,
not a substitute for that fingerprint's own recovery path. Recovery of
an already-completed creation operation under the fingerprint's own
rules returns the recorded outcome without re-running this section's
verification a second time, exactly as that rule already states;
committing a `jti` in step 10 is what makes that recovery safe to skip
re-verification against, since the original commit already proves the
assertion was checked once. A fresh submission bearing a `jti` this AS
has never seen follows the full ten-step procedure above regardless of
whether it shares a creation fingerprint with an unrelated prior
request.

## Recorded Facts {#intent-admission-facts}

On success, the verified output `facts` this type designates for
recording as a `submission_evidence` element
({{I-D.draft-mcguinness-oauth-mission}}) are closed to exactly:

`admission_issuer`:
: REQUIRED. The assertion's `iss`.

`originator`:
: REQUIRED. The assertion's `originator`.

`presenter`:
: REQUIRED. The assertion's `presenter`.

`admission_basis`:
: REQUIRED. The assertion's `admission_basis`.

`status`:
: REQUIRED. The assertion's `status`, as observed at admission; see
  {{intent-admission-security}} for what this does and does not prove
  afterward.

These facts are exactly the normalized form a `submission_evidence`
element's `facts` member carries for this type
({{I-D.draft-mcguinness-oauth-mission}}); this document defines no
independent commitment over them beyond the Mission Record's own
trust, matching the OAuth binding's stated position that it commits
none. A future profile whose threat model needs an independently
committed root over Mission-record-derived facts, including this
evidence, MAY reference the Mission Record's `submission_evidence`
array as that normalized input without redefining its shape; this
document takes no position on whether or how such a root is
constructed.

## The Intent Admission Payload Type {#intent-admission-payload-type}

`mission-intent-admission` is a Mission Evidence Envelope payload type
({{evidence-payload-type-registry}}).

**Producer authorization** ({{producer-authorization}}), instantiated
for this type:

* `emitter.role` MUST be `issuer`; no other role is permitted for this
  type.
* `emitter.id` MUST equal the canonical identity of the Mission issuer
  named by `mission.issuer`, or a component that issuer specifically
  registers to emit this type on its behalf; it MUST NOT be accepted
  merely because it is a string equal to some other value the instance
  carries.
* The JWS signing key MUST be one `mission.issuer` (or its specifically
  registered component) publishes for Mission Evidence Envelope
  signing; a verifier MUST NOT accept a key merely because it resolves
  and validates, if that key is not published by the named issuer for
  this purpose. A valid, resolvable key belonging to a different
  issuer, presented over an instance naming this Mission, MUST be
  rejected under this rule even though the envelope integrity check of
  {{mission-evidence-envelope-integrity}} would otherwise pass.

An AS SHOULD emit one instance at Mission creation when the approved
submission carried Intent Admission Evidence, giving that admission an
independently signed, portable, registrable record instead of leaving
it as unanchored Mission Record metadata alone.

`payload` is closed to exactly:

`intent_hash`:
: REQUIRED. A string. The admitted Mission's `intent_hash`
  ({{I-D.draft-mcguinness-oauth-mission}}).

`submission_evidence`:
: REQUIRED. An array. The Mission Record's `submission_evidence` array
  ({{I-D.draft-mcguinness-oauth-mission}}), restated exactly, in the
  record's order.

`disposition`:
: REQUIRED. A string. `admitted` is the only value this document
  defines: this payload type is emitted only where a Mission exists to
  reference, so no refusal outcome is representable by it. A companion
  needing richer admission-outcome semantics registers a new payload
  type rather than extending this one's closed schema
  ({{evidence-payload-type-registry}}).

Beyond {{mission-evidence-envelope-integrity}} and the producer
authorization above, a verifier holding the referenced Mission Record
MUST confirm `payload.intent_hash` and `payload.submission_evidence`
are byte-for-byte equal, member for member, to the Mission Record's
own `intent_hash` and `submission_evidence`.

**This is an AS attestation, not independent proof of the original
assertion.** A verifier that has done all of the above has confirmed
that the Mission issuer itself attests to having admitted this exact
intent under this exact recorded evidence; it has not independently
verified the admission issuer's original Intent Admission Assertion,
because the payload carries only `submission_evidence`'s digest and
extracted facts ({{intent-admission-facts}}), never the assertion
bytes themselves, and the cross-check above compares two
representations that are both under the Mission issuer's own control.
A party requiring independent proof of what the admission issuer
signed must obtain the retained assertion artifact, or a resolvable
reference to it plus its digest, and verify it directly under
{{intent-admission-verification}}; this document does not require a
Mission issuer to retain or disclose that artifact, and states no
disclosure or access rule for one that is retained voluntarily. A
deployment that intends independent verifiability should retain the
assertion (or a digest-referenced pointer to it) and define its own
disclosure policy.

## Worked Example {#intent-admission-example}

An Intent Submission Evidence entry presenting an Intent Admission
Assertion:

~~~ json
{
  "type": "mission-intent-admission-assertion",
  "assertion": "eyJhbGciOiJFUzI1NiIsImtpZCI6ImFkbWlzc2lvbi1rZXktMSIsInR5cCI6Im1pc3Npb24taW50ZW50LWFkbWlzc2lvbi1hc3NlcnRpb24randzIn0..."
}
~~~

The Mission Evidence Envelope instance the AS emits after admitting
it:

~~~ json
{
  "type": "mission-intent-admission",
  "id": "evt_9K2nP4qV9rL3tY6sB1zN0eF7jB1zN6cQ",
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "issuer": "https://as.example"
  },
  "emitter": { "id": "https://as.example", "role": "issuer" },
  "occurred_at": "2026-11-02T08:00:05Z",
  "sequence": 0,
  "payload": {
    "intent_hash": "sha-256:3q4-...",
    "submission_evidence": [
      {
        "type": "mission-intent-admission-assertion",
        "artifact_hash": "sha-256:9zP-...",
        "verified_at": "2026-11-02T08:00:04Z",
        "facts": {
          "admission_issuer": "https://admission.example",
          "originator": { "iss": "https://admission.example", "sub": "user-42" },
          "presenter": { "client_id": "agent-client-7" },
          "admission_basis": { "type": "helpdesk-ticket", "reference": "TCK-88123" },
          "status": "active"
        }
      }
    ],
    "disposition": "admitted"
  },
  "evidence_envelope": {
    "format": "jws-compact",
    "value": "eyJhbGciOiJFUzI1NiIsImtpZCI6ImFzLWtleS0xIn0..."
  }
}
~~~

Three negative cases the verification procedure above refuses, none
of which are pinned as byte-level vectors at this Experimental
maturity:

**Cross-issuer signature.** A component holding a valid, resolvable
signing key for `https://as-b.example` signs an otherwise well-formed
`mission-intent-admission` instance whose `mission.issuer` is
`https://as-a.example`. The envelope integrity check
({{mission-evidence-envelope-integrity}}) passes: the signature is
valid and the bytes match. Producer authorization
({{intent-admission-payload-type}}) fails: the key is not one
`https://as-a.example` publishes, so the instance is rejected.

**Concurrent replay.** Two submissions presenting assertions with the
same `jti` arrive concurrently. Exactly one wins the atomic reservation
of verification step 7; the other observes reservation failure and is
refused as replay, never processed to a second, independent admission
decision.

**Cross-JOSE-type substitution.** A JWS validly signed by a key
resolvable in the admission issuer's key set, but whose protected
`typ` is some other profile's value (or absent), is presented as an
Intent Admission Assertion. Verification step 2 rejects it before
signature verification is even meaningful for this purpose: the
protected `typ` does not equal
`mission-intent-admission-assertion+jws`.

# Conformance {#conformance}

This document defines conformance for three roles: a PRODUCER that
emits Mission Evidence Envelope instances; a VERIFIER that reads and
checks them; and, for Intent Admission Evidence specifically, the AS
that processes the inbound assertion.

A PRODUCER conforming to this document MUST:

* emit only instances whose `type` is registered
  ({{evidence-payload-type-registry}});
* sign every instance under {{mission-evidence-envelope-integrity}},
  with a `kid` resolvable under {{producer-authorization}} for the
  named `mission.issuer`, `emitter.role`, and `type`; and
* retain, or successfully deliver to a designated collector, every
  instance it emits, per {{mission-evidence-envelope-retention}}.

A VERIFIER conforming to this document MUST:

* reject an instance whose `type` it does not recognize, applying no
  default or guessed schema ({{evidence-payload-type-registry}});
* perform the five-step procedure of
  {{mission-evidence-envelope-integrity}}, including the producer
  authorization check of step 5, and treat a failure at any step as
  not-verified; and
* apply the compromise-boundary rule of
  {{mission-evidence-envelope-integrity}} where the resolved signing
  key is identified as compromised.

An AS supporting Intent Admission Evidence MUST:

* perform the ten-step procedure of {{intent-admission-verification}}
  for every `mission-intent-admission-assertion` entry presented,
  including the atomic `jti` reserve/commit/release discipline of step
  7 and step 10;
* record the verified facts exactly as {{intent-admission-facts}}
  fixes; and
* where it emits a `mission-intent-admission` instance, satisfy the
  producer-authorization instantiation and the byte-equality
  cross-check of {{intent-admission-payload-type}}.

# Security Considerations {#security-considerations}

## Envelope and Registry

A shared media type and a shared JWS `typ` across every registered
payload type do not, by themselves, prevent a well-signed instance
from naming a Mission or role its signer has no relationship to; that
is exactly the gap {{producer-authorization}} closes, and a payload
type registration that omits an executable producer-authorization
check is non-conforming under {{evidence-payload-type-registry}}, not
merely incomplete. A Designated Expert reviewing a new registration
({{iana}}) MUST confirm the verification-procedure reference actually
specifies this check; a registration whose "verification procedure"
is only the generic five-step integrity algorithm, with no
type-specific authorization binding, does not satisfy the registry's
own requirement.

Producer authorization is bound to the key the named Mission issuer
(or its specifically registered component) publishes. Compromise of
that key defeats producer authorization the same way it would defeat
any other signature-based control; this document adds no independent
defense against a compromised issuer key beyond the general
compromise-boundary rule of {{mission-evidence-envelope-integrity}}.

## Intent Admission {#intent-admission-security}

**Key-use separation.** Requiring a key scoped specifically to Intent
Admission Assertion signing, and a distinct protected `typ`
({{intent-admission-assertion}}), defends against a cross-protocol
substitution: without both, a JWS validly issued for an unrelated
purpose under the same multipurpose key could otherwise be
misinterpreted as an Intent Admission Assertion, since generic JWS
validation alone does not distinguish one profile's tokens from
another's.

**Atomic replay control.** Checking whether a `jti` has been consumed
and then separately recording it as consumed is a check-then-act race:
two concurrent submissions can both observe the identifier as unused
before either records it. The atomic reserve of
{{intent-admission-verification}} step 7 closes this by making the
reservation itself the race's single winner-take-all point, rather
than treating "check" and "consume" as two independent operations a
concurrent request can interleave between.

**Status is a point-in-time attestation, not a live check.** Verifying
`status == active` at verification step 10 establishes only that the
admission issuer's state was `active` when it signed the assertion. It
does not establish that the upstream admission decision remains valid
at any later time, including at the moment a verifier later inspects a
retained `mission-intent-admission` instance or `submission_evidence`
element. A deployment whose threat model requires currently-valid
admission status, not merely status-at-signing, MUST define its own
mechanism for checking current status against the admission issuer;
this document provides none, and the absence of a later revocation
check is not a gap this document's conformance requirements cover.

**The emitted record is not independent proof of the inbound
assertion.** See {{intent-admission-payload-type}}: a verifier that
trusts only the Mission issuer's own attestation, without separately
verifying the original Intent Admission Assertion or a retained
reference to it, has not independently corroborated what the admission
issuer signed.

# Privacy Considerations {#privacy-considerations}

## Envelope and Registry

A Mission Evidence Envelope instance's `emitter`, `mission`, and
`payload` members may carry identifiers correlatable across a
Mission's evidence stream; a registered payload type states its own
minimization guidance where its payload carries personal data. This
document states none for the generic envelope beyond what
{{intent-admission-facts}} states for Intent Admission Evidence.

## Intent Admission

The Intent Admission Assertion's `originator`, and the `facts`
recorded under {{intent-admission-facts}}, identify a natural person;
`admission_basis.reference` further identifies an external ticketing
or consent record. A deployment retaining `mission-intent-admission`
payload instances SHOULD apply access control and retention discipline
proportionate to that sensitivity, and MUST NOT resolve
`admission_basis.reference` to disclose more of the upstream record
than the admission issuer's own disclosure policy permits.

# IANA Considerations {#iana}

This document requests the following IANA actions.

## Media Type Registry

This document registers two media types per {{RFC6838}}: the Mission
Evidence Envelope's JSON representation and its JWS-secured
representation, shared by every registered payload type.

### Mission Evidence Envelope Media Type

- Type name: application
- Subtype name: mission-evidence+json
- Required parameters: none
- Optional parameters: none
- Encoding considerations: binary; JSON encoded in UTF-8
- Security considerations: see {{security-considerations}}
- Interoperability considerations: see this document
  ({{mission-evidence-envelope}})
- Published specification: this document
- Applications that use this media type: any registered Mission
  Evidence Envelope payload type ({{evidence-payload-type-registry}})
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

### Secured Mission Evidence Envelope Media Type

- Type name: application
- Subtype name: mission-evidence+jws
- Required parameters: none
- Optional parameters: none
- Encoding considerations: binary; a JWS Compact Serialization:
  base64url-encoded values separated by period characters. The
  secured payload's own media type is always
  `application/mission-evidence+json`, carried in the JWS protected
  `cty` ({{mission-evidence-envelope-integrity}}).
- Security considerations: see {{security-considerations}}
- Interoperability considerations: see this document
  ({{mission-evidence-envelope-integrity}})
- Published specification: this document
- Applications that use this media type: any registered Mission
  Evidence Envelope payload type ({{evidence-payload-type-registry}})
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

## Mission Evidence Payload Type Registry {#iana-evidence-payload-types}

IANA is requested to create the "Mission Evidence Payload Types"
registry. The registration policy is Specification Required
{{RFC8126}}. A Designated Expert reviews a submission for the
discipline {{evidence-payload-type-registry}} and
{{producer-authorization}} require: a `Type` value that is a
collision-resistant name, not already registered; a stable `Payload
Schema Reference` fixing a closed schema for `payload`; a stable
`Verification Procedure Reference` fixing, beyond the shared envelope
integrity procedure ({{mission-evidence-envelope-integrity}}), every
check a consumer applies to that payload, including an executable
producer-authorization binding of emitter, signing key, and permitted
`emitter.role` values to the named `mission.issuer` and `type`
({{producer-authorization}}); and a `Producer` naming the principal or
principal class, and permitted `emitter.role` values, authoritative
for instances of the type.

A Designated Expert MUST reject a registration whose verification
procedure reference does not fully specify payload verification and
producer authorization, or whose `Type` would require reinterpreting
an already-registered type's schema or semantics rather than adding a
new one ({{mission-evidence-envelope-domain-separation}}). A
Designated Expert MAY approve a same-`Type` update to an existing
registration's schema or verification-procedure reference where the
change controller demonstrates it is compatible (accepts no bytes an
existing conforming instance would not already satisfy, and
reinterprets no existing member) and preserves a change history;
approval of an incompatible change requires a new `Type`.

Each registration records:

- **Type**: the payload type's collision-resistant string value.
- **Payload Schema Reference**: the specification and section
  defining the closed `payload` schema.
- **Verification Procedure Reference**: the specification and section
  defining the type-specific verification procedure, including its
  producer-authorization binding.
- **Producer**: the principal or principal class, and permitted
  `emitter.role` values, authoritative for instances of this type.
- **Change Controller**: IETF, or the registrant for any other
  registration.
- **Reference**: the specification defining the type.

This document seeds the registry with the payload type it defines:

| Type | Payload Schema Reference | Verification Procedure Reference | Producer | Change Controller | Reference |
|---|---|---|---|---|---|
| `mission-intent-admission` | this document, {{intent-admission-payload-type}} | this document, {{intent-admission-payload-type}} | Mission issuer (`emitter.role` `issuer`) | IETF | this document, {{intent-admission-evidence}} |

Each further document that defines a Mission Evidence Envelope payload
type requests that type's registration in its own IANA considerations,
carrying its Internet-Draft reference as a publication dependency
under this registry's policy until it is published.

--- back

# Document History {#document-history}

\[\[ To be removed from the final specification ]]

Initial version. Defines the Mission Evidence Envelope, the Mission
Evidence Payload Type Registry, and Intent Admission Evidence as the
registry's first payload type and the first consumer of the OAuth
binding's Intent Submission Evidence dispatch (#506). Extracted as a
standalone, binding-neutral companion, rather than hosted inside
Mission Runtime Evidence, so that a consent-only, approval-time, or
other non-runtime evidence producer never depends on PDP/PEP decision
and execution record machinery merely to use the shared envelope
(review of PR #721, responding to the #282 architecture-shape finding
and the #512 disposition on Intent Admission). Incorporates review
findings: an explicit Producer Authorization section binding
emitter/key to (Mission issuer, type) rather than trusting a resolved
signature alone; a protected JWS `typ`, mandatory-algorithm, and
key-use-separation requirement for the inbound Intent Admission
Assertion; an atomic `jti` reserve/commit/release replay control,
composed explicitly with the OAuth binding's creation-fingerprint
idempotent recovery so the two mechanisms do not read as competing; a softened
payload-type change-control rule permitting compatible clarification
and security hardening under the same `type`, reserving a new `type`
for incompatible schema or semantic change; an explicit statement that
the emitted `mission-intent-admission` record is the Mission issuer's
own attestation, not independent proof of the admission issuer's
original assertion; a stated limitation that admission status is
checked only at signing time, never re-verified against later
revocation; and an assigned retention obligation (the producer, or a
designated collector on successful delivery). A non-normative
Migration Plan section responds to the review's request that this
document not become "a permanent parallel envelope": no existing
evidence kind is migrated by this document, and whether one migrates
is left to that kind's own specification.

# Acknowledgments
{:numbered="false"}

This document responds to the 2026-08-24 architecture-shape review's
P1 finding 10 and to issues #282, #512, #506, and #699. The author
thanks the Mission-Bound Authorization implementer community for
feedback.
