---
title: "Mission Substrate Requirements"
abbrev: "Mission Substrate"
category: std

docname: draft-mcguinness-mission-substrate-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - mission
 - agent
 - authorization
 - substrate
 - binding
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-substrate.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC4648:
  RFC6234:
  RFC6920:
  RFC7493:
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
  I-D.draft-mcguinness-mission-authority-server:
    title: "Mission Authority Server"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-authority-server.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-aauth:
    title: "Mission Context Binding for AAuth"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-aauth.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-uma:
    title: "Mission-Bound Authorization for UMA 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-uma.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-gnap:
    title: "Mission-Bound Authorization for GNAP"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-gnap.html
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
  I-D.draft-mcguinness-mission-architecture:
    title: "An Architecture for Mission-Bound Authorization"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-architecture.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-status:
    title: "Mission Status and Lifecycle for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-status.html
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
  I-D.draft-mcguinness-mission-audit:
    title: "Mission Audit Transparency"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-audit.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-security-model:
    title: "Mission Security Model"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-security-model.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

--- abstract

A Mission binds an actor to approved context under the governance of
an identified controller.  Authorization substrates realize that
relationship in materially different ways.  Some carry structured
authority in credentials; others keep contextual policy at an online
service and use substrate-native authorization at each resource.

This document defines a small, substrate-neutral Mission kernel and a
set of separately claimable capabilities.  The kernel covers a native
Mission reference, controller and actor binding, approved context, an
approval event, an active/non-active governance gate with bounded
reliance, context propagation, and an ordered governance record.
Optional capabilities cover lifecycle gating, state observation,
structured authority,
monotonic derivation, credential binding, independent verification,
and portable evidence.  A Mission Substrate Statement declares which
capabilities a binding supplies and the limits of each claim.

The contract deliberately does not require OAuth identifiers or issuer
semantics, a particular authorization-details format, a universal
Authority Set or subset algebra, a JWT claim, or common intent and
authority hashes.

--- middle

# Introduction

A Mission is a durable contextual-governance relationship created by
an approval event.  It associates an actor and approved context with
an identified controller, gives that relationship a stable reference,
and makes subsequent governance decisions attributable to it.

That common relationship does not imply a common authorization model.
For example, an OAuth deployment can derive a portable, structured
authority envelope and carry it in an access token
({{I-D.draft-mcguinness-oauth-mission}}).  A standalone Mission
Authority Server (MAS) can manage the relationship without issuing the
resource credential that exercises authority
({{I-D.draft-mcguinness-mission-authority-server}}).  An AAuth Person
Server can keep contextual Mission data private while scopes,
resource-owned policy, and per-hop authorization decisions provide
deterministic resource access ({{I-D.draft-mcguinness-mission-aauth}}).

Treating the first model as the minimum contract would force the other
models to emulate OAuth mechanics.  It would also make a claim such as
"Mission substrate" ambiguous: a consumer could not tell whether it
meant contextual governance, portable authority, current-state
enforcement, or independently verifiable evidence.

This document therefore defines:

* a contextual-governance kernel that every conforming Mission
  Substrate Binding provides ({{kernel}});
* optional, independently declared capabilities ({{capabilities}});
* rules for profiles that consume only the capabilities they need
  ({{composition}}); and
* a Mission Substrate Statement that makes each binding's guarantees
  and limits checkable ({{statement}}).

The architectural relationship among Mission specifications is
described informationally in
{{I-D.draft-mcguinness-mission-architecture}}.  This document is the
normative contract for substrate-neutral claims.

## Scope and Non-Goals {#scope}

This document standardizes the semantics a binding exposes, not the
wire representation used to expose them.  It does not define an
approval endpoint, credential format, state protocol, authority
language, evidence format, or identifier syntax.

In particular, the kernel does not require:

* an OAuth `client_id`, Authorization Server, or OAuth issuer
  identifier;
* JSON, JWT, or a member named `mission`;
* `authorization_details` or any other particular structured
  authorization language;
* one global Authority Set or a subset relation that applies across
  administrative or protocol boundaries;
* `intent_hash`, `authority_hash`, or any common set of integrity
  anchors; or
* disclosure of the approved context to a resource or other
  downstream consumer.

A binding MAY use any of those mechanisms.  When it does, their
guarantees arise from the binding and the capabilities it claims, not
from the kernel.

This document is designed to be adopted on its own.  Conformance
requires no other document, and the kernel vocabulary is defined
entirely here.  The Mission-Bound Authorization family uses this
document as its binding-neutral contract; the family vocabulary
mapping, the scoped precedence rule for the OAuth-native binding, and
the change-ownership rule are collected in {{family}} and are not
needed by an adopter outside that family.

# Status: A Normative Contract for Bindings {#doc-status}

<!-- family-status: BEGIN (generated from family-manifest.json; exact-matched by scripts/check-family-manifest.mjs) -->
Maturity: stable. Maintenance: active.
Adopt when: Runtime implementers consume its commitment construction and kernel contract; binding authors profile it.
Requires: nothing beyond its listed references.
<!-- family-status: END -->

# Conventions and Terminology {#conventions-and-terminology}

{::boilerplate bcp14-tagged}

This document uses the following terms:

Actor:
: The agent, service, workload, person, or other entity whose
  operations are governed in the Mission context.  A binding defines
  how the Actor is identified and authenticated.  "Actor" is not
  synonymous with OAuth `client_id`.

Approver:
: The person, policy authority, or other accountable party that makes
  the approval decision through the binding's native ceremony.

Approved Context:
: The task description, purpose, instructions, boundaries, or other
  contextual material to which the Approver agreed.  It can be
  machine-readable, human-readable, opaque to consumers, or a
  combination.  It is not necessarily an authorization policy.

Controller:
: The identified authority responsible for the Mission's approval,
  governance state, and governance record.  A binding can distribute
  these functions, but it identifies the party accountable for them
  and describes the trust relationships among the components.
  "Controller" does not imply OAuth token issuance.

Mission Context:
: The durable relationship among a Controller, Actor, Approved
  Context, approval event, governance state, and governance record.

Mission Reference:
: The substrate-native value, or tuple of values, that identifies one
  Mission Context within a defined Controller namespace.

Mission Substrate Binding:
: A specification that maps the Mission Context kernel and zero or
  more optional capabilities onto an authorization substrate and
  claims conformance to this document.

Mission Substrate Statement:
: The section of a Mission Substrate Binding that declares the
  binding's kernel mapping and optional capabilities ({{statement}}).

Positive governance decision:
: A Controller decision that approves, permits, or continues an
  operation specifically by relying on the Mission Context.  It does
  not include an independent resource authorization decision that
  does not rely on that context.

{{family}} maps these terms to the vocabulary of the Mission-Bound
Authorization family.

# Contextual-Governance Kernel {#kernel}

Every Mission Substrate Binding MUST provide all requirements in this
section.  Meeting the kernel means only that a substrate carries
Mission contextual governance.  It does not by itself mean that
authority is portable, machine-evaluable, monotonically derived,
credential-bound, or independently verifiable.  It does mean that no
reliance derived from a Mission is unbounded ({{bounded-reliance}}).

| Kernel duty | The binding defines |
| --- | --- |
| Native reference and Controller ({{reference}}) | A stable, non-reassigned Mission Reference, its uniqueness namespace, how unguessability is met where the reference is disclosed beyond the Controller, and how relying components identify the Controller |
| Authority roles ({{authority-roles}}) | The authorities responsible for the functions it uses; roles never collapse silently |
| Actor binding ({{actor-binding}}) | The Actor handle, its authenticated establishment at approval, and how later decisions establish the acting party |
| Approved context and immutability ({{approved-context}}) | The immutable approved value or a verifiable commitment to it, distinct from mutable operational fields |
| Approval event ({{approval}}) | A native ceremony that atomically creates an active Mission from an authenticated approval |
| Basic governance gate ({{basic-gate}}) | An active predicate; positive decisions only while active, and every unrecognized condition fails closed |
| Bounded reliance ({{bounded-reliance}}) | A stated reliance bound on every positive decision and every Mission-governed artifact |
| Context propagation ({{propagation}}) | The join between decisions or artifacts and the Mission Reference, and exactly what that join proves |
| Ordered governance record ({{governance-record}}) | An integrity-protected, ordered, attributable record of governance events |
{: title="Kernel duties at a glance"}

## Native Reference and Controller {#reference}

A binding MUST define a Mission Reference that is:

* stable for the lifetime and retention period of the Mission
  Context;
* unambiguous within the Controller namespace declared by the
  binding; and
* never reassigned to a different Mission Context within that
  namespace.

If the native reference is not globally unambiguous, the binding MUST
define the Controller identifier or other namespace value with which
it is compared.  A reference can be random, content-addressed,
sequential within a protected namespace, or a substrate-native tuple.
The kernel does not impose a particular syntax.  A reference
disclosed beyond the Controller MUST NOT be guessable by parties
outside the Mission's authorized set: a binding satisfies this with
at least 128 bits of reference entropy, with a reference derived from
content that is not disclosed beyond that set, or by confining a
predictable reference to a namespace whose every keyed surface
authenticates the caller and does not disclose existence.

The binding MUST define how a relying component identifies the
Controller responsible for the reference.  This can be local
configuration, a protocol identifier, a trust anchor, or another
substrate-native mechanism.  A binding MUST NOT describe a bare value
as globally identifying a Mission when its uniqueness actually
depends on unstated local context.

## Authority Roles {#authority-roles}

A binding identifies the authorities responsible for the functions it
uses.  Roles MAY be co-located in one implementation, but their
semantics remain distinct, and a provider statement MUST NOT use
colocation to imply that one role's assertion establishes another
role's fact.  The roles are:

* the approval authority;
* the lifecycle authority;
* the accountable owner;
* the approved-context commitment authority;
* the Actor identity authority;
* the deployment or workload identity authority, where applicable;
* the authority-source authority, where structured authority is
  composed;
* the artifact projection or credential issuer;
* the resource decision authority;
* the correlation or joining authority; and
* the evidence authority.

The kernel requires the approval and lifecycle authorities.  The
other roles appear when the corresponding capability is claimed.
Higher-assurance profiles can require preventive or evidentiary
independence between roles; the kernel requires only that they never
collapse silently ({{capability-confusion}}).

## Actor Binding {#actor-binding}

At approval, the Controller MUST bind the Mission Context to the
Actor identity, key, workload identity, authenticated session, or
other actor handle defined by the binding.  The value MUST be derived
from authenticated context or verified proof; it MUST NOT be accepted
solely from an unauthenticated proposal.

The binding MUST state:

* what the Actor handle identifies;
* how the Controller establishes it at approval; and
* how a later positive governance decision establishes that the
  acting party is the bound Actor or an authorized delegate.

The kernel does not require the same identifier syntax at every hop.
A binding that maps between identifiers MUST define which component
performs the mapping and the assurance and ambiguity of that mapping.

## Approved Context and Immutability {#approved-context}

The binding MUST maintain either the Approved Context itself or a
verifiable commitment to it.  After approval, the approved value MUST
be immutable.  Mutable operational fields, including current state
and log entries, MUST be distinguishable from the approved value.

Changing the Approved Context requires a new approval event and a new
Mission Reference, unless a binding defines the change as approval of
a new immutable version with its own unambiguous reference.  A binding
MUST NOT silently replace the approved value behind an existing
reference.

When a binding uses a commitment instead of retaining or disclosing
the value, it MUST define:

* the exact committed bytes or canonicalization procedure;
* algorithm identification and algorithm-agility behavior;
* domain separation sufficient to prevent cross-type substitution;
  and
* how a party that possesses the value verifies the commitment.

The commitment can be a native content address, a digest, a signed
object, or another binding-defined construction.  The kernel does not
require two distinct commitments for descriptive context and
structured authority.  A binding that retains the Approved Context at
every governance party satisfies this section through the maintained
value; a native content address it also uses as the Mission Reference
is then verification material for parties holding the value, not a
commitment in place of it.  A default construction a binding MAY
adopt for these duties is defined in {{default-commitment}}.

## Approval Event {#approval}

A binding MUST define a native approval ceremony that atomically
creates an active Mission Context or has equivalent transactional
semantics.  The ceremony MUST:

1. authenticate the Approver at the assurance level required by the
   deployment;
2. establish the Actor as specified in {{actor-binding}};
3. present or otherwise make available to the Approver a faithful
   representation of the context being approved;
4. record the approval decision, Approver, Actor binding, Approved
   Context or its commitment, Mission Reference, and Controller; and
5. initialize the Mission as active only after the approval succeeds.

If the context being approved changes between presentation and the
approval decision, the ceremony MUST NOT create the Mission Context
without the Approver's consent to the changed context, and any
commitment is computed over the context actually approved.

Presentation requirements are substrate-specific.  A binding MUST
identify security-relevant material supplied by an untrusted proposer
and describe how the approval ceremony prevents it from being
mistaken for Controller-derived policy or trusted explanation.

The kernel does not require the Approved Context to enumerate every
resource operation.  If the ceremony approves structured authority,
the binding claims and follows the Structured Authority capability
({{structured-authority}}).

## Basic Governance Gate {#basic-gate}

Every binding MUST define an active predicate and a non-active
outcome.  The underlying state vocabulary can be as small as
`active` and `terminated`, or can contain additional native states
and reasons.

The Controller MUST make a positive governance decision only while
the Mission is active.  Every value or condition not recognized as
active MUST fail closed for that decision.  A non-active Mission can
remain available for audit and can be the subject of denial or cleanup
decisions.

This rule governs decisions made by relying on the Mission Context. It
does not assert that every downstream authorization decision is a
derivation from the Mission, nor that every resource can observe
current Mission state.  Those stronger properties require optional
capabilities.

The binding MUST define at least one authenticated means by which an
authorized party can cause the Mission to become non-active.  It MUST
identify the authorized parties and the effect of the transition on
subsequent Controller decisions.  A binding MAY express completion,
revocation, expiry, or supersession as reasons without making each a
distinct protocol state.

## Bounded Reliance {#bounded-reliance}

Authority derived from a Mission MUST NOT be usable indefinitely.
For every positive decision under {{basic-gate}}, and for every
credential or other artifact the binding describes as governed by the
Mission, the binding MUST state a reliance bound in at least one of
two forms:

* the decision point establishes that the Mission is active when the
  decision is made, and the binding states the maximum interval during
  which the result or artifact remains usable after the Mission
  becomes non-active; or
* the artifact carries an expiry, and the binding states how that
  expiry is bounded by or disclosed with the Approved Context.

A decision or artifact with neither bound does not conform, and a
stated bound SHOULD NOT exceed the interval the Mission's purpose
requires.  This floor requires no consumer-facing freshness source: a binding whose
credential lifetimes sit inside the Mission's own bound satisfies it
unmodified, as the OAuth binding's stateless baseline does.  The bound
gives the non-active transition of {{basic-gate}} its force: a party
who causes a Mission to become non-active is assured that reliance
under the Mission ends within the stated interval.

## Context Propagation {#propagation}

Each positive governance decision and each artifact that a binding
claims is Mission-governed MUST carry, or be unambiguously joinable
to, the Mission Reference and Controller namespace.  The binding MUST
define the join and the party that performs it.

Propagation can occur in a credential, a decision response, a
protected protocol exchange, a local execution context, or an audit
record.  Merely accepting an unverified reference supplied by the
Actor does not establish Mission governance.

The binding MUST state what the propagation mechanism proves.  In
particular, it MUST distinguish among:

* correlation with a Mission Context;
* proof that the Controller made a particular decision;
* proof that a credential was issued under that Mission; and
* proof that a requested operation is within approved structured
  authority.

The kernel requires only the first property with authenticated or
integrity-protected provenance from the Controller.  The remaining
properties require binding-specific mechanisms and, where applicable,
optional capabilities.

## Ordered Governance Record {#governance-record}

The Controller MUST maintain an integrity-protected, ordered record of
governance events for the Mission.  At minimum, the record MUST cover
approval, positive and negative Controller decisions that rely on the
Mission Context, and transition to a non-active outcome.  Events MUST
be attributable to their source and correlated with the Mission
Reference.

The ordering mechanism can be a sequence, trusted timestamp plus a
defined tie-break rule, append position, or another unambiguous native
mechanism.  The binding MUST state its ordering semantics, integrity
protection, authorized readers, and retention period.  The retention
period MUST include the active lifetime and a declared post-termination
period.

This record need not be portable or independently verifiable.  A
binding that makes either claim also supplies the corresponding
capability in {{capabilities}}.

# Default Commitment Construction {#default-commitment}

Any specification that defines a commitment, a Mission Substrate
Binding or an importing profile alike, MAY satisfy the commitment
duties of {{approved-context}}, for the Approved Context and for any
other artifact it commits, with the following default construction.
The OAuth issuance profile
({{I-D.draft-mcguinness-oauth-mission}}) instantiates it, and family
profiles import it from this section; a specification with a native
or member-named commitment (a content address, a signed object, a
digest whose member name fixes the algorithm) remains free to use
that instead, stating its own algorithm identification and agility
behavior under the duties of {{approved-context}}.

The default commits to bytes in one of three species, and a
specification defining a commitment classifies it:

* **Envelope anchor**: SHA-256 {{RFC6234}} over the JCS {{RFC8785}}
  canonical bytes of a closed JSON object carrying exactly three
  members and no others: `typ`, a string naming the committed
  object, collision-resistant because a namespace the defining
  specification controls qualifies it; `iss`, a string whose value
  the defining commitment specifies; and `value`, the committed
  JSON value.
* **Canonical-object digest**: SHA-256 over the JCS serialization of
  a normalized JSON object without the envelope, where protocol
  context already fixes what is committed.
* **Raw-octet digest**: SHA-256 over an exact,
  specification-defined octet sequence, with no canonicalization: a
  whole artifact as exchanged, or the UTF-8 encoding of a defined
  scalar value.

The envelope's `iss` is a namespace binding that domain-separates
commitments across issuing authorities; it does not authenticate
whoever computed the commitment, which stays a signature or evidence
property. A digest is encoded as an algorithm prefix followed by the
base64url, no-padding {{RFC4648}} encoding of the digest: `sha-256:`
identifies SHA-256, which is mandatory to implement and the only
algorithm defined.

Every committed JSON value, and the envelope around it, MUST satisfy
I-JSON {{RFC7493}}, and the party computing or verifying a
commitment MUST reject non-conformant input before canonicalization:
externally received JSON destined for commitment is parsed by a
duplicate-detecting parser, and an object carrying duplicate member
names is rejected at parse time, before the parsed data model
exists; string data is valid Unicode, free of the surrogate and
noncharacter code points I-JSON prohibits, and is preserved
unchanged; number data supplied to JCS is representable as a finite
IEEE 754 binary64 value ({{RFC8785}}, Section 3.1). The commitment is over the parsed I-JSON data value,
not the source text; a value needing exact decimal or large-integer
semantics rides as a string or under a stricter declared numeric
domain.

The algorithm prefix is the agility mechanism. A new algorithm
enters only through a new prefix defined by a referencing
specification, its name drawn from the Named Information Hash
Algorithm Registry ({{RFC6920}}). A verifier MUST reject a digest
whose algorithm prefix it does not recognize and MUST NOT treat an
unrecognized prefix as `sha-256`. No transition mechanism is
defined: every commitment a current carrier defines is a single
prefixed string, and a specification introducing a new prefix MUST
define the carrier and schema of any parallel commitment, the
binding that proves the old and new values commit to the same
object, producer behavior during the transition, verifier selection
and downgrade behavior when recognition sets differ, and the
transition procedure itself.

The OAuth binding's Integrity Anchor Test Vectors
({{I-D.draft-mcguinness-oauth-mission}}) give a byte-level worked
example of the envelope-anchor species alone (`intent_hash`,
`proposal_hash`, `authority_hash`); an implementation can check its
own computation against them. The canonical-object and raw-octet
species above, the parse-time duplicate-detection rule, the I-JSON
numeric domain, and the reject-unknown-prefix and no-downgrade
agility rules remain prose-only: no vector pins them.

# Optional Capabilities {#capabilities}

Capabilities are additive claims.  A binding MUST NOT claim a
capability unless it meets every requirement in that capability's
subsection.  A capability can be scoped to particular modes, roles,
operations, or deployments; such scope is part of the claim and MUST
appear in the Mission Substrate Statement.

Absence of a capability is not partial conformance.  It means that a
consumer requiring that property does not compose with the binding in
that mode.

| Capability | Property claimed |
| --- | --- |
| Lifecycle-Gated Authorization ({{lifecycle-gated}}) | Named authorization operations are gated on currently active state |
| State-Observable ({{state-observable}}) | An authenticated source lets a named consumer determine whether a Mission is active |
| Structured Authority ({{structured-authority}}) | A machine-evaluable authority representation with an identified semantics owner |
| Monotonic Derivation ({{monotonic-derivation}}) | Covered derivations verify a no-broader-than relation within a declared boundary |
| Credential-Bound ({{credential-bound}}) | An integrity-protected association between an artifact and exactly one Mission, with selected fact semantics |
| Authorized Context Correlation ({{authorized-context-correlation}}) | An authorized association among independently established facts, made by an identified joining authority |
| Independently Verifiable ({{independently-verifiable}}) | A named consumer verifies a specified property without an online query to the Controller |
| Portable Evidence ({{portable-evidence}}) | Evidence crosses a stated administrative boundary and verifies there |
{: title="Optional capabilities at a glance"}

## Lifecycle-Gated Authorization {#lifecycle-gated}

A binding claiming **Lifecycle-Gated Authorization** extends the
basic governance gate to named authorization operations.  Its
Statement MUST enumerate those operations, such as authority
derivation, delegation, credential issuance, credential refresh,
permission decisions, or continued reliance.

For every operation in the claim, the decision point MUST establish
that the Mission is currently active before returning a positive
result.  It MUST fail closed when current state cannot be established
within the binding's stated freshness bound.  The binding MUST state
the maximum interval during which a previously issued positive result
can remain usable after the Mission becomes non-active.

A binding can therefore claim this capability for Controller-issued
permission decisions while not claiming it for independently issued
resource tokens.  It MUST NOT generalize the narrower claim to the
uncovered path.

## State-Observable {#state-observable}

A binding claiming **State-Observable** MUST expose at least one
authenticated, integrity-protected source from which a named consumer
can determine whether a Mission is active.  For each source, the
Statement MUST identify:

* the authorized consumers;
* the state vocabulary and active predicate;
* authentication and integrity protection;
* the freshness or maximum staleness bound; and
* fail-closed behavior for unavailable, invalid, or unknown state.

The source MAY return native state names.  A projection onto another
protocol's vocabulary MUST preserve the active/non-active distinction;
an unknown or non-active native value MUST NOT project to active.

State-Observable does not by itself require a consumer to check state.
That enforcement property is claimed by Lifecycle-Gated Authorization
or by a consuming runtime profile such as
{{I-D.draft-mcguinness-mission-runtime}}.

## Structured Authority {#structured-authority}

A binding claiming **Structured Authority** MUST define a
machine-evaluable representation of authority associated with the
Mission and MUST identify the authority that owns the representation's
semantics.  The Statement MUST specify:

* the representation and its version or type-identification rules;
* how resources, operations, and constraints are interpreted;
* which decision points consume it;
* whether it is approved context, Controller-derived policy, a
  resource-owned policy input, or a decision result; and
* the scope in which two values can be compared.

Different resources or administrative domains MAY use different
authority languages.  This capability does not create a universal
Authority Set, require RFC 9396 authorization details, or imply that
arbitrary values have a meaningful subset relation.

Where constraints admit comparison, the binding MUST define
comparison in the constraint's value space.  Unknown types or
constraints MUST fail closed at a decision point that requires their
semantics.

## Monotonic Derivation {#monotonic-derivation}

A binding claiming **Monotonic Derivation** MUST also claim Structured
Authority for the values covered by the derivation.  It MUST define a
no-broader-than relation for those values and the protocol boundary
within which that relation is valid.

Every derivation, delegation, or attenuation operation included in
the claim MUST verify that its result is no broader than its declared
parent under that relation.  Unsupported or incomparable values MUST
fail closed.  The Statement MUST identify each narrowing point and
the component that performs the comparison.

Every covered transition is classified as exactly one of:

`preserve`:
: the same authoritative fact remains applicable across the
  transition;

`attenuate`:
: the result's validity derives from a provable no-broader-than
  relationship to its declared parent under the claimed relation; or

`decide_anew`:
: a target-recognized authority makes a fresh decision under its own
  policy.

Incomparability routes to refusal or to `decide_anew`; a translation
between vocabularies is never silently treated as attenuation.

The claim can cover a single authorization language or delegation
chain.  It MUST NOT be presented as constraining fresh authorization
decisions made under a different resource-owned policy or at an
uncovered protocol hop.  A binding can correlate those decisions with
the same Mission while leaving them outside this capability; in the
classification above those decisions are `decide_anew`.

## Credential-Bound {#credential-bound}

A binding claiming **Credential-Bound** MUST define an
integrity-protected association between a credential or authorization
artifact and exactly one Mission Reference and Controller namespace.
It MUST identify:

* the protected fields or join inputs that establish the association;
* the credential or artifact issuer and verifier trust relationship;
* how the credential is bound to the Actor or authorized delegate;
* substitution and replay protections; and
* whether issuance or refresh is covered by Lifecycle-Gated
  Authorization.

The association MAY be a JWT claim, another credential field, a
protected protocol parameter, or a verified join.  A reference copied
from Actor-controlled input without Controller or credential-issuer
validation does not satisfy this capability.

A Credential-Bound claim MUST select which of the following fact
semantics the mechanism establishes, and a claim MUST NOT say
"Mission-bound" without that selection:

* correlation only;
* artifact issuance under the Mission;
* authority derivation under the Mission;
* lifecycle-gated issuance; or
* current state as of an observation.

These are separate facts: none follows from another, they provide
different assurance, and the issued-under and correlation-only
semantics MUST NOT share an unqualified claim.  Actor or presenter
proof is a separate element of the claim: a bearer artifact can be
Mission-bound under any of these semantics while offering a weaker
holder guarantee.

## Authorized Context Correlation {#authorized-context-correlation}

A binding claiming **Authorized Context Correlation** MUST supply an
authorized association among independently established facts, such as
the Mission, the Subject, the Actor (and the Deployment and executing
instance where the binding distinguishes them), an authority
artifact, a request or transaction, and a target resource.  The claim
MUST identify the joining authority, the association policy, the
proof inputs, conflict handling, the association's lifetime and
revocation, its audience, and its substitution protection.

Matching strings or timestamps do not satisfy this capability: the
association is an authorized fact established by the joining
authority, not an observation that two values coincide.  This
capability is required whenever one authority did not itself bind all
required facts in the applicable context ({{context-splicing}}).

Native binding does not automatically supply this capability. It
supplies it where it authoritatively joins independently established
facts and satisfies the joining-authority, policy, proof,
conflict-handling, lifetime, audience, and substitution requirements
above; one authority can perform that join, and being the same
authority does not make the facts co-established. Where a binding's
facts are genuinely co-established at issuance or decision time,
nothing independently established remains to join, and its Statement
says `not supplied` with that reason rather than presenting native
binding as a join.

## Independently Verifiable {#independently-verifiable}

A binding claiming **Independently Verifiable** MUST let the named
consumer verify a specified Mission property without an online query
to the Controller.  The Statement MUST enumerate the properties, for
example Controller approval, context commitment, credential binding,
structured authority, or state as of a signed observation.

For every property, the binding MUST define the verification artifact,
canonical input, trust anchor or key discovery mechanism, algorithm
agility, validity interval, and revocation or freshness limitations.
Verification failure or an unsupported algorithm MUST fail closed.

Independent verification of a signature does not establish current
state unless the artifact and its validity rules provide that
property.  It also does not make private Approved Context available or
turn contextual governance into a machine-evaluable policy language.

## Portable Evidence {#portable-evidence}

A binding claiming **Portable Evidence** MUST define evidence that can
be transferred across the administrative boundary stated in the
claim and verified there.  The Statement MUST identify:

* each evidence type and the event or decision it represents;
* its binding to the Mission Reference, Controller, Actor where
  appropriate, and relevant decision or artifact;
* canonical bytes, integrity protection, and verification procedure;
* ordering, duplicate handling, and correlation semantics;
* retention and key-availability periods; and
* disclosure, minimization, and unlinkability considerations.

Portable Evidence MAY reveal only a commitment to Approved Context.
The capability does not require disclosure of the context itself.
Signed receipts, Mandates, or transparency statements can supply this
capability when their profiles meet these requirements
({{I-D.draft-mcguinness-mission-mandate}},
{{I-D.draft-mcguinness-mission-audit}}).

# Composition by Capability {#composition}

A substrate-neutral profile MUST declare the kernel functions and
optional capabilities it consumes.  It MUST NOT infer an undeclared
capability from the generic statement that a binding supports
Missions.

Examples include:

* a profile that only correlates Controller decisions and log entries
  can consume the kernel;
* action-time termination enforcement consumes State-Observable and
  a lifecycle-gating rule at the relevant enforcement point;
* offline attenuation consumes Structured Authority, Monotonic
  Derivation, Credential-Bound, and usually Independently Verifiable;
* cross-domain audit consumes Portable Evidence and whatever
  underlying property the evidence proves; and
* resource-side policy evaluation consumes Structured Authority only
  when that representation is defined for the resource.  A Mission
  reference alone is not structured authority.

Where a binding lacks a required capability, a profile can define an
explicit adapter or join.  The adapter's specification MUST state the
new trust assumptions, what it proves, what it cannot prove, and its
failure behavior.  The adapter then supplies the capability; the
kernel does not acquire it retroactively.

Capability claims compose only over their declared scope.  For
example, an online Controller decision can be lifecycle-gated while a
previously issued resource token remains valid until expiry, and one
authority language can support monotonic delegation while a later
resource-owned decision is independent.  Specifications MUST preserve
those boundaries rather than describe the whole deployment with the
stronger local property.

# Mission Substrate Conformance {#conformance}

This document defines conformance for a specification.  An
implementation conforms to the binding specification it implements.

A conforming Mission Substrate Binding:

1. defines every element of the contextual-governance kernel in
   {{kernel}};
2. publishes a Mission Substrate Statement as specified in
   {{statement}};
3. claims only optional capabilities whose complete requirements it
   satisfies in the claimed scope; and
4. defines fail-closed behavior when a required reference, binding,
   state, authority value, commitment, proof, or capability cannot be
   established.

There are no "full" and "partial" provision levels.  Those labels
hide which guarantees are actually present.  The capability list and
scope in the Mission Substrate Statement are the conformance result.

## Mission Substrate Statement {#statement}

A specification that itself claims conformance to this document
MUST contain a section titled "Mission Substrate Statement".  For a
specification that makes no such claim, this document MAY instead
publish a **Mapping Assessment**: this document's own normative
assessment of how that specification realizes the kernel and
capabilities, in the Statement's form ({{family}} carries one for
the OAuth binding).  A Mapping Assessment is not the described
specification's conformance result, and no such result exists
unless a specification claims conformance itself; the assessment
binds this document's readers (family documents use it as the
mapping), and the described specification neither claims nor takes
any requirement from it.  Either form MUST identify the
specification version and mode to which it applies.

For the kernel, the Statement MUST provide a checkable mapping for:

1. the Mission Reference, its uniqueness namespace, comparison rules,
   retention, non-reassignment rule, and how the unguessability
   requirement of {{reference}} is met;
2. the Controller identity and how relying components establish it;
3. the Actor handle, its authentication at approval, later Actor
   binding, delegation if any, and identifier mappings;
4. the Approved Context, its immutable boundary, and any commitment
   and verification procedure;
5. the native approval ceremony and each step of {{approval}};
6. the active predicate, non-active outcome, authorized transition
   mechanisms, and effect on subsequent Controller decisions;
7. the reliance bound of {{bounded-reliance}} for each decision and
   Mission-governed artifact class: the stated maximum residual
   interval, the expiry rule, or both;
8. every propagation or join surface claimed to establish Mission
   governance and the exact property each surface proves; and
9. governance-record event coverage, ordering, integrity, access, and
   retention.

The Statement MUST then include a capability table with one row for
each capability in {{capabilities}}.  Each row MUST say `supplied` or
`not supplied`: a capability is supplied in a named scope when the
row's stated activation conditions hold, or it is not supplied.
There is no third state.  An activation condition states separately
what a specification defines, what an implementation supports, what
a deployment enables, and where the resulting property applies.  A
supplied row MUST:

* cite the binding sections that satisfy the capability;
* state its mode and operational scope;
* state its activation conditions: the extension, deployment
  configuration, or cooperating component that must hold for the
  property to be supplied in that scope, or `always`;
* state its temporal elements: the fact's freshness at use, the
  decision or artifact lifetime, and the residual interval after the
  Mission becomes non-active, each stated directly or expressly
  inherited from the reliance floor of {{bounded-reliance}};
* state its failure behavior for absent, stale, unknown,
  incomparable, invalid, or unavailable input; and
* list material limitations.

An extension can itself publish a provider claim as a Statement
extension; a deployment profile declares which extensions and
activation conditions are active.

The following is a non-normative skeleton:

| Capability | Claim | Activation | Scope and defining sections | Limitations |
| --- | --- | --- | --- | --- |
| Lifecycle-Gated Authorization | supplied | always | Controller permission decisions | Previously issued resource credentials expire independently |
| State-Observable | supplied | Status extension active | Status responses | Maximum staleness is deployment-configured |
| Structured Authority | not supplied | -- | -- | Approved Context is descriptive |
| Monotonic Derivation | not supplied | -- | -- | No authority comparison relation is defined |
| Credential-Bound | supplied | always | Native authorization artifact | Covers correlation, not context disclosure |
| Authorized Context Correlation | supplied | Verified join active | Join assertions | Joining authority is the Controller |
| Independently Verifiable | supplied | Signed receipt profile active | Signed receipts | Proves approval as of issuance, not current state |
| Portable Evidence | not supplied | -- | -- | Governance record is Controller-local |
{: title="Illustrative Mission Substrate Statement capability table"}

A real Statement also carries each supplied row's temporal elements
and failure behavior; the skeleton omits those columns for width.

Text outside the Statement cannot silently broaden a capability claim.
If another specification adds a capability, that specification MUST
publish an updated Statement or a Statement extension that identifies
the base binding and precise added scope.

# Security Considerations

## Capability Confusion {#capability-confusion}

The principal risk this document addresses is capability confusion:
treating Mission correlation as proof of authority, an approval as
proof of current state, a local narrowing relation as a universal
subset rule, or a signed artifact as proof of facts it does not carry.
Consumers need to match every required property to an explicit
capability claim and its scope.

A secure implementation fails closed when a required capability is
absent, claimed with unmet activation conditions, or outside its
declared scope.
It does not upgrade a kernel-only reference because its syntax
resembles a credential claim or content digest.

## Reference and Context Substitution

The Controller namespace is part of Mission identity whenever a
reference is not globally unique.  Omitting it permits references from
one Controller to be substituted at another.  A content-addressed
reference additionally depends on correct canonicalization, domain
separation, and algorithm identification; a random or sequential
reference depends on the Controller's protected lookup.

Actor, context, credential, and decision bindings need to cover the
same Mission Reference and Controller namespace.  An implementation
that joins values from different namespaces or accepts an Actor-supplied
reference without authentication can attribute unrelated authority or
activity to a Mission.

## Context Splicing {#context-splicing}

An attacker can combine valid identity evidence, a valid credential,
and a valid Mission from different transactions.  Each piece verifies
on its own; the composite is unauthorized.  Authorized Context
Correlation ({{authorized-context-correlation}}) is required whenever
one authority did not itself bind all required facts in the
applicable context, and a consumer MUST NOT treat co-presentation of
independently valid facts as an authorized association.

## Controller Compromise

The Controller is trusted for the kernel properties it asserts.  A
compromised Controller can approve false context, bind the wrong Actor,
make false decisions, suppress governance events, or report false
state.  Independently Verifiable and Portable Evidence can make some
misbehavior detectable or attributable, but do not prevent a trusted
Controller from making a malicious decision.  The broader threat
model is analyzed by {{I-D.draft-mcguinness-mission-security-model}}.

Where Controller functions are distributed, the binding's Statement
needs to expose the trust and authentication between approval, state,
decision, logging, and credential components.  Naming one logical
Controller does not eliminate those internal trust boundaries.

## State and Residual Authority

The kernel's non-active outcome stops new positive Controller
governance decisions.  It does not automatically invalidate every
artifact previously issued or stop a resource that cannot observe
state.

Lifecycle-Gated Authorization and State-Observable claims must
state their coverage and residual interval.  Short credential lifetime
can bound residual authority but is not instantaneous termination.

The bounded-reliance floor ({{bounded-reliance}}) guarantees that a
stated bound exists on every conforming path; it does not make any
bound short.  A bound long enough to be vacuous defeats the floor's
purpose; consumers evaluate the stated interval, not only its
presence.

## Governance Record Integrity

An ordered record that is not externally witnessed can still be
truncated or rewritten by a compromised Controller.  The kernel
requires integrity protection against unauthorized modification, not
public transparency.  Deployments needing third-party detection of
equivocation or truncation require Portable Evidence or a separate
transparency profile.

# Privacy Considerations {#privacy-considerations}

Mission References are correlation handles.  Reusing them across
resources or administrative domains can reveal that otherwise
unrelated actions belong to one task.  Bindings SHOULD disclose a
reference only to components that require Mission correlation and
SHOULD prefer audience-specific derived handles where cross-context
correlation is unnecessary.

Approved Context can contain sensitive instructions, resource names,
personal data, and business purpose.  The kernel allows it to remain
at the Controller and allows downstream surfaces to carry only a
reference or commitment.  A binding SHOULD minimize context in
credentials, state responses, and evidence and MUST document the
additional disclosure introduced by Structured Authority,
Independently Verifiable, or Portable Evidence claims.

Governance records create durable behavioral histories.  Bindings
need access control, declared retention, deletion policy after the
retention period, and minimization of Actor and Approver identifiers.
Integrity commitments and predictable Mission References can
themselves become stable correlation values, and a commitment can
enable guessing attacks when the committed context has low entropy.

# IANA Considerations

This document has no IANA actions.

--- back

# Binding Mapping Guidance {#crosswalk}

This appendix is informative.  Four bindings publish their own
normative Mission Substrate Statements, and this document publishes
its Mapping Assessment of the OAuth binding
({{oauth-statement}}): the standalone MAS
({{I-D.draft-mcguinness-mission-authority-server}}), AAuth
({{I-D.draft-mcguinness-mission-aauth}}), UMA
({{I-D.draft-mcguinness-mission-uma}}), and GNAP
({{I-D.draft-mcguinness-mission-gnap}}) bindings each publish their
own.  Those Statements, not this appendix, are the authoritative
capability claims.  This appendix illustrates the mapping method
through three design poles among which a new substrate can locate
itself.

## OAuth-Native Mapping: The Broad-Claims Pole

The OAuth binding can intentionally claim a broad set of capabilities.
Its Authorization Server can act as Controller, OAuth identifiers can
instantiate Actor and subject mappings, and protected access-token
fields can supply Credential-Bound.  Registered authorization-detail
types can supply Structured Authority: each type's semantics owner
defines its operations, constraints, and comparison behavior, and
Rich Authorization Requests are the carrier, not the semantics.  Its defined subset relation can support
Monotonic Derivation within the authorization-detail types and
operations covered by that relation.

Those are strengths of the OAuth binding, not kernel requirements.
State observation is supplied when a status, introspection, or
signals mechanism such as
{{I-D.draft-mcguinness-oauth-mission-status}} is active.  Independent
verification is limited to the properties actually present in a
verifiable credential; current state and undisclosed context do not
follow from a Mission identifier or hash alone.

## Standalone MAS Mapping: The Separation-and-Join Pole

The MAS separates Mission governance from an otherwise unchanged
Authorization Server.  It can satisfy the kernel and can provide
Structured Authority and Monotonic Derivation for operations it owns.
It does not, by itself, prove that an OAuth access token was issued
under a Mission.

A verified join can establish correlation, and a
cooperating credential issuer can add stronger lifecycle and
credential-binding properties.  The MAS Statement needs to describe
those with their activation conditions and preserve the boundary
between MAS assertions and Authorization Server behavior.

## AAuth-Native Mapping: The Private-Context Pole

An AAuth Mission naturally implements the contextual-governance
kernel: the Person Server (PS) controls approval and contextual decisions,
the native Mission reference identifies the approved blob, and the
Mission log records governance interactions.  The private mission
description need not be a machine-evaluable authorization policy.

Deterministic access can remain with scopes, Access Server policy, or
a resource-owned structured policy language.  Such a language can
claim Structured Authority, and possibly Monotonic Derivation, only
inside the boundary where its semantics and comparison relation are
defined.  A fresh downstream authorization decision is not required
to be a subset of a single upstream Mission Authority Set.

Credential-Bound and Lifecycle-Gated Authorization claims need to be
made per AAuth access mode.  A PS-issued authorization artifact can
carry a protected native Mission reference and be gated at issuance;
an independently issued resource credential does not acquire those
properties merely because the agent also has a Mission.  Similarly, a
PS-local log supplies the kernel governance record but not Portable
Evidence.  State management, signed evidence, and resource-verifiable
structured decisions are useful AAuth extensions rather than baseline
kernel requirements.

# Mission-Bound Authorization Family Use {#family}

This appendix is normative for documents of the Mission-Bound
Authorization family and informative for every other adopter.  An
adopter outside the family does not need it.

The family's earlier documents, including the published OAuth binding
({{I-D.draft-mcguinness-oauth-mission}}), use the vocabulary this
contract was generalized from.  The terms correspond as follows:

| This document | Family documents |
| --- | --- |
| Mission Context | Mission |
| Mission Reference | Mission Identifier |
| Controller | Mission Issuer, where the binding issues; natively the AS, MAS, UMA authorization server, or AAuth PS |
| Actor | the authenticated acting client or agent |
| Approver | Approver |
| Approved Context | the Mission Intent, the recorded authority proposal where one was submitted, and the derived Authority Set |
| Ordered governance record | the Mission log, assessment log, or audit record |
{: title="Family vocabulary mapping"}

A family document that maps its own vocabulary to the kernel's MUST
use these correspondences.

The authority-role map ({{authority-roles}}) aligns with the OAuth binding's
Authority Sources: the `authority_source` record member and its three
sources (user-delegated, service-owned, organizational) are the OAuth
binding's realization of the authority-source authority role, and its
source ceiling is that role's assertion staying within the named
source's authority.

Precedence is scoped, not global.  For the OAuth-native binding, the
OAuth binding's definitions govern that mapping; this document governs
the kernel and capability vocabulary.  The dependency is one-way and
creates no cycle: this appendix takes a normative reference to the
OAuth binding, the specification its Mapping Assessment is asserted
against, while the OAuth binding takes no normative dependency on
this document (its pointer back is informative, and the family
manifest's typed edges record it as such).

Ownership migrates by touch, not by relocation.  When a
binding-neutral definition next changes substantively, the change
MUST land in this document, and the owning family section becomes a
reference to it; no change is ever made solely to move words.

## OAuth Binding Mapping Assessment {#oauth-statement}

<!-- assessed-oauth-digest: f602b0b28121a838 -->

This section is this document's Mapping Assessment of the OAuth
Mission binding ({{I-D.draft-mcguinness-oauth-mission}}), published
under {{statement}}.  The assessment is normative as this
document's own content: this document asserts, and maintains
against the OAuth binding's text, the kernel mapping and capability
claims below.  It is not the OAuth binding's conformance result:
the OAuth binding makes no substrate-conformance claim and takes no
requirement from this document; its pointer to this section is
informative on its side, and the two documents' no-mutual-dependency
rule stands.
It applies to the OAuth binding edition published from the same
repository revision as this document (the two editions revise and
publish in lockstep, so the assessed revision is exact; for a copy
obtained independently of the repository, the family's conformance
manifest publishes the assessed binding's content digest in its
`source.specs` entry, identifying the exact assessed bytes), in the
binding's base single-domain mode with the OPTIONAL capabilities as
the activation conditions below state, and to the kernel and
capability vocabulary of this document.  The OAuth binding's own definitions
govern every mapped construct; this assessment claims no property the
OAuth binding does not define.

For the kernel:

1. The Mission Reference is `mission_id`: high-entropy, unambiguous
   within the issuer namespace, compared by exact string equality
   together with `mission.issuer`, never reassigned, retained for the
   audit horizon, and disclosed beyond the issuer only on the
   binding's authorized surfaces.
2. The Controller is the Mission Issuer (the Authorization Server),
   established through `mission.issuer` and the deployment's issuer
   trust (AS metadata and published keys).
3. The Actor handle is the authenticated OAuth client at approval;
   the external Subject is fixed by the OAuth binding's injective mapping;
   delegates ride the `act` chain; child and successor lineage is
   recorded through the parent and predecessor members; actor-type
   classification uses `sub_profile` and instance assertions where
   deployed.
4. The Approved Context is the Mission Intent recorded verbatim, the
   recorded authority proposal where one was submitted, and the
   derived Authority Set; the immutable boundary is the record's
   immutable members; commitments are the typed integrity anchors
   (`intent_hash`, `proposal_hash`, `authority_hash`); a material
   change obtains a new approval through an expansion successor.
5. The approval ceremony is the OAuth binding's approval event: authenticated
   Approver, the distinct-approver rule for write-bearing Missions,
   rendering of the derived Authority Set and the effective expiry,
   and atomic record commit, with deferred, interactive, and dispatch
   realizations.
6. The active predicate is stored `state` equal to `active` with
   the decision time strictly before the record's effective
   `expires_at`, the issuer materializing the resulting `expired`
   transition lazily where it chooses; any other stored value,
   recognized or not, is non-active; transitions are authenticated
   lifecycle operations; a non-active Mission refuses issuance and
   derivation.
7. The reliance bound is the record's effective `expires_at` (never
   later than the requested ceiling), which caps every derived
   credential's `exp`; the maximum residual after a Mission becomes
   non-active is the outstanding credential lifetime, bounded by the
   deployment's declared access-token TTL.
8. The propagation and join surfaces are: the `mission` claim
   (artifact issuance under the Mission, authority derivation, and
   lifecycle-gated issuance); the `mission_id` and
   `mission_expires_at` response members (correlation only); the
   introspection projection (state as of the response, caller
   authorization and minimization applying); the Status surfaces
   (state as of a signed observation with explicit freshness); and
   the grant binding (the issuer's native association of Mission,
   Subject, client, and credential).
9. The governance record is the Mission Record with its approval
   evidence and lifecycle history, retained for the audit horizon,
   with integrity resting on record custody and the typed anchors.

The capability table:

| Capability | Claim | Activation | Scope and defining sections | Limitations |
| --- | --- | --- | --- | --- |
| Lifecycle-Gated Authorization | supplied | always | State-gated issuance and every derivation gate | Outstanding credentials run to their own `exp`; the residual is bounded, not zero |
| State-Observable | supplied | Status, introspection, or Signals companion active | Those surfaces | Staleness bounded by each surface's declared freshness |
| Structured Authority | supplied | always | `authorization_details` of AS-supported types, each type's own specification defining semantics (for `mission_resource_access`, the Mission Resource Access Profile's Common Constraints) | Semantics exist per supported type, not universally |
| Monotonic Derivation | supplied | always | The subset rule over covered types at every derivation, delegation, and attenuation point | Covered transitions are `attenuate`; a cross-vocabulary transition is `decide_anew`, never silent attenuation |
| Credential-Bound | supplied | always | The `mission` claim on issued tokens | Fact semantics: issuance under the Mission, authority derivation, lifecycle-gated issuance; state-as-of only via the State-Observable surfaces |
| Authorized Context Correlation | supplied | the Delegation role active ({{I-D.draft-mcguinness-oauth-mission}}) | The Token Exchange join at delegated issuance: the AS, as joining authority, joins the Mission and Subject carried by the Mission-bound `subject_token` with the delegate identity independently established by the `actor_token` or the delegate's own client authentication, binding both to the newly issued credential | The base grant binding at issuance co-establishes its facts and is not a join; cross-authority joins are the Mission Authority Server's machinery, not this binding's |
| Independently Verifiable | supplied | Mandate, signed Status, or audit companion active | Anchor recomputation and signed artifacts per those profiles | Signature verification never establishes current state |
| Portable Evidence | supplied | Evidence, Mandate, or audit companion active | Per those profiles | The governance record is otherwise issuer-local |
{: title="OAuth Mission binding capability table"}

Temporal elements: every issued credential's `exp` is capped by the
record's effective `expires_at`; state observations carry their
surface's declared freshness; the residual after non-active is the
outstanding credential lifetime under the deployment's declared TTL.
Failure behavior: an unknown lifecycle state is non-active; an
unresolvable reference, a failed anchor verification, and an unknown
`authorization_details` type fail closed; where a row's activation
condition does not hold, the property is not supplied and a consumer
MUST NOT rely on it.

The OAuth binding's three OPTIONAL implementation roles, which its
Conformance section names OPTIONAL capabilities
({{I-D.draft-mcguinness-oauth-mission}}), are surfaces an
implementation may or may not offer, each independent of the others. The capability table above states scoped guarantee
claims: properties the OAuth binding supplies and the conditions
under which each is supplied. The two vocabularies answer different
questions and are not equivalent; the entries below relate them
without collapsing one into the other. Declaring an OPTIONAL role
never creates a claim beyond the eight already stated above.

Introspection:
: Exercises State-Observable.  One of State-Observable's three named
  activation surfaces, alongside Status and Signals; declaring it
  activates that otherwise-conditional claim.

Delegation:
: Exercises Lifecycle-Gated Authorization, Structured Authority,
  Monotonic Derivation, Credential-Bound, and Authorized Context
  Correlation.  The OAuth binding's delegation subset-checks
  `authorization_details`, carries the `mission` claim unchanged,
  sender-constrains the delegated credential to the delegate's own
  key, and refuses issuance unless the Mission is active.  The Token
  Exchange that issues the delegated credential is itself a grant
  binding at issuance: the AS joins the Mission and Subject carried
  by the Mission-bound `subject_token` with the delegate identity
  established by the `actor_token` or the delegate's own client
  authentication, binding both to the newly issued credential.  Four
  of the five claims are supplied always, and Delegation exercises
  them rather than creating them; Authorized Context Correlation is
  the exception, activated by this role, whose Token Exchange join
  is its supplier.  The `act` chain itself supplies none of them: it
  is attribution, never authority.

Cross-Domain:
: Exercises Lifecycle-Gated Authorization, Structured Authority,
  Monotonic Derivation, and Credential-Bound.  Carries these four
  always-supplied guarantees across the domain hop: the Mission
  reference and `authority_hash` intact, authority that only
  narrows, and projection gated on active state, while adding an
  interoperable projection surface the guarantees alone do not
  provide.  It does not become Portable Evidence by crossing a
  domain: that claim activates only when an Evidence, Mandate, or
  audit companion is active, and Cross-Domain is not among them.


# Acknowledgments
{:numbered="false"}

This document refines the substrate interface first consolidated
informationally by the architecture document.  The author thanks the
Mission-Bound Authorization implementer community for feedback.
