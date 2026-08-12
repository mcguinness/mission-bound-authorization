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

informative:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
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
  I-D.draft-mcguinness-mission-aauth:
    title: "Mission Context Binding for AAuth"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-aauth.html
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
({{I-D.draft-mcguinness-mission-authority-server}}).  An AAuth Policy
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

# Conventions and Terminology

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
commitment in place of it.

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
unmodified, as the OAuth core's stateless baseline does.  The bound
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

# Optional Capabilities {#capabilities}

Capabilities are additive claims.  A binding MUST NOT claim a
capability unless it meets every requirement in that capability's
subsection.  A capability can be scoped to particular modes, roles,
operations, or deployments; such scope is part of the claim and MUST
appear in the Mission Substrate Statement.

Absence of a capability is not partial conformance.  It means that a
consumer requiring that property does not compose with the binding in
that mode.

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

The claim can cover a single authorization language or delegation
chain.  It MUST NOT be presented as constraining fresh authorization
decisions made under a different resource-owned policy or at an
uncovered protocol hop.  A binding can correlate those decisions with
the same Mission while leaving them outside this capability.

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

The Statement MUST distinguish a credential cryptographically issued
under the Mission from a credential merely correlated with a Mission
by an external join.  Either can be useful, but they provide different
assurance and MUST NOT share an unqualified claim.

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

A Mission Substrate Binding MUST contain a section titled "Mission
Substrate Statement".  It MUST identify the specification version and
mode to which the statement applies.

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
each capability in {{capabilities}}.  Each row MUST say `supported`,
`not supported`, or `conditional`.  A supported or conditional row
MUST cite the binding sections that satisfy the capability, state its
mode and operational scope, and list material limitations.  A
conditional row MUST state the extension, deployment property, or
cooperating component that supplies the condition.

The following is a non-normative skeleton:

| Capability | Claim | Scope and defining sections | Limitations |
| --- | --- | --- | --- |
| Lifecycle-Gated Authorization | supported | Controller permission decisions | Previously issued resource credentials expire independently |
| State-Observable | conditional | Status extension | Maximum staleness is deployment-configured |
| Structured Authority | not supported | -- | Approved Context is descriptive |
| Monotonic Derivation | not supported | -- | No authority comparison relation is defined |
| Credential-Bound | supported | Native authorization artifact | Covers correlation, not context disclosure |
| Independently Verifiable | conditional | Signed receipt profile | Proves approval as of issuance, not current state |
| Portable Evidence | not supported | -- | Governance record is Controller-local |
{: title="Illustrative Mission Substrate Statement capability table"}

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
absent, conditional but unavailable, or outside its declared scope.
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
state.  Lifecycle-Gated Authorization and State-Observable claims must
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

# Privacy Considerations

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

This appendix is informative.  It illustrates how existing Mission
architectures map to the capability model.  It is not a substitute for
the normative Mission Substrate Statement published by each binding,
and an extension or deployment can change a row.

| Capability | OAuth Mission | Standalone MAS | AAuth Mission |
| --- | --- | --- | --- |
| Contextual-governance kernel | Native Mission record, AS controller, OAuth client/subject mappings | Native Mission record, MAS controller, explicit join boundary | Native Mission reference and PS-controlled contextual Mission |
| Lifecycle-Gated Authorization | AS gates covered token issuance and derivation | MAS gates its own decisions; OAuth credential issuance requires a cooperating credential issuer | PS gates covered permission or token decisions; coverage depends on the AAuth access mode |
| State-Observable | Conditional on Status, introspection, or signal support | Conditional on the exposed MAS status mechanism | Not implied by the private Mission blob; requires a management or state extension for other consumers |
| Structured Authority | OAuth authorization details and their type-specific semantics | Can use the OAuth Mission authority representation | Not inherent in the Mission description; scopes or a resource-owned structured language can supply it for their own decision boundary |
| Monotonic Derivation | Applies where the OAuth profile defines and checks its no-broader-than relation | Applies to MAS-governed authority operations; not automatically to an unchanged AS | Not a baseline cross-hop property; a structured resource policy can define monotonicity within its own vocabulary |
| Credential-Bound | Mission-bound OAuth credential | Not supplied by the MAS alone; conditional on a verified join or cooperating credential issuer | Native Mission reference can be credential-bound where the PS or federated AS carries and validates it; not every access mode does |
| Independently Verifiable | Possible where signed credentials expose the property and verification material | Conditional on signed artifacts and the property they expose | A resource can verify a credential, but cannot thereby independently verify private contextual Mission content or the PS's full reasoning |
| Portable Evidence | Supplied only by evidence, Mandate, or audit profiles that define portable artifacts | Likewise conditional on an evidence profile | A PS-local Mission log is not portable evidence; signed receipts or checkpoints would be an extension |
{: title="Illustrative capability mapping for existing architectures"}

## OAuth-Native Mapping

OAuth Mission can intentionally claim a broad set of capabilities.
Its Authorization Server can act as Controller, OAuth identifiers can
instantiate Actor and subject mappings, Rich Authorization Requests
can supply Structured Authority, and protected access-token fields can
supply Credential-Bound.  Its defined subset relation can support
Monotonic Derivation within the authorization-detail types and
operations covered by that relation.

Those are strengths of the OAuth binding, not kernel requirements.
State observation remains conditional on a status, introspection, or
signals mechanism such as
{{I-D.draft-mcguinness-oauth-mission-status}}.  Independent
verification is limited to the properties actually present in a
verifiable credential; current state and undisclosed context do not
follow from a Mission identifier or hash alone.

## Standalone MAS Mapping

The MAS separates Mission governance from an otherwise unchanged
Authorization Server.  It can satisfy the kernel and can provide
Structured Authority and Monotonic Derivation for operations it owns.
It does not, by itself, prove that an OAuth access token was issued
under a Mission.  A verified join can establish correlation, and a
cooperating credential issuer can add stronger lifecycle and
credential-binding properties.  The MAS Statement needs to describe
those as conditional capabilities and preserve the boundary between
MAS assertions and Authorization Server behavior.

## AAuth-Native Mapping

An AAuth Mission naturally implements the contextual-governance
kernel: the Policy Server controls approval and contextual decisions,
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

The family's earlier documents, including the published OAuth core
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

Precedence is scoped, not global.  For the OAuth-native binding, the
core's definitions govern that mapping; this document governs the
kernel and capability vocabulary.  Neither document depends
normatively on the other.

Ownership migrates by touch, not by relocation.  When a
binding-neutral definition next changes substantively, the change
MUST land in this document, and the owning family section becomes a
reference to it; no change is ever made solely to move words.

# Acknowledgments
{:numbered="false"}

This document refines the substrate interface first consolidated
informationally by the architecture document.  The author thanks the
Mission-Bound Authorization implementer community for feedback.
