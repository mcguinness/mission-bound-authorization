---
title: "Mission-Bound Authorization Capability Model"
abbrev: "Mission Capability Model"
category: info

docname: draft-mcguinness-mission-capability-model-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - mission
 - authorization
 - capability
 - adoption
 - oauth
 - aauth
 - governance
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-capability-model.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC2119:
  RFC8174:
  I-D.draft-mcguinness-mission-framework:

informative:
  RFC6749:
  RFC9396:
  RFC9728:
  I-D.draft-mcguinness-mission-oauth-profile:
  I-D.draft-mcguinness-mission-aauth-profile:
  I-D.draft-mcguinness-mission-mas:
  I-D.draft-mcguinness-mission-runtime-profile:
  I-D.draft-mcguinness-mission-shaper-profile:
  I-D.draft-mcguinness-mission-migration:
  I-D.draft-mcguinness-oauth-rfc9728bis:

--- abstract

This document defines a substrate-neutral capability and adoption
model for Mission-Bound Authorization. Capability is reported as a
coordinate on three axes: the Capability Ladder (Levels 0 through 5),
Resource Server Tiers (RS-A through RS-D), and Authorization Domain
Tiers (AD-1 through AD-3). The document names three adoption claims
(Mission-Bound Issuance, Mission-Bound Runtime Enforcement, and
Mission-Bound Cross-Domain Projection) that map onto the coordinate,
and describes how OAuth-only, AAuth-only, and cross-substrate
deployments report against the coordinate. The capability-advertisement
metadata registry is created by the Mission Framework; this document
provides the formal registry entries for the four metadata fields and
the closed enumerations for the three axes. This document is
Informational: conformance is claimed against substrate or runtime
profile specifications, and the coordinate here is a reporting
vocabulary.

--- middle

# Introduction

The Mission-Bound Authorization architecture is composed of a
framework specification and several profile specifications. A
deployment that implements some subset of these profiles delivers
some subset of the architecture's governance and enforcement
capabilities. Different deployments will sit at different points of
maturity, in different substrates, and with different Resource Server
behavior, for reasons that are appropriate to their environment. A
single conformance label cannot describe these positions without
either flattening real differences or implying that every deployment
should climb to the top of one ladder.

This document defines a capability and adoption vocabulary for
Mission-Bound Authorization. The vocabulary treats capability as a
coordinate on three independent axes:

- The **Capability Ladder** (Levels 0 through 5) describes end-to-end
  maturity of Mission governance and enforcement across the
  deployment.
- **Resource Server Tiers** (RS-A through RS-D) describe what an
  individual Resource Server does with a Mission-bound credential at
  request time.
- **Authorization Domain Tiers** (AD-1 through AD-3) describe what an
  authorization domain (an OAuth Authorization Server, an AAuth
  Person Server, or a Mission Authority Server) delivers to its
  clients, downstream domains, and Resource Servers.

A deployment reports a coordinate composed of one value from each
axis, optionally per Resource Server and per authorization domain,
together with the scope of the claim and the substrate profile
versions it implements. The coordinate preserves detail that one
score would hide and prevents contradictory claims such as a Level 4
deployment whose consequential actions all pass through RS-A
Resource Servers.

Three named adoption claims sit above the coordinate as headline
signals: Mission-Bound Issuance, Mission-Bound Runtime Enforcement,
and Mission-Bound Cross-Domain Projection. Each maps to a coordinate
range on the three axes. They are convenient labels for sentences in
release notes and case studies; they are not independent
interoperability or certification claims.

This document is Informational. Conformance is claimed against the
testable wire requirements of a substrate profile or the Runtime
Enforcement Profile. The Capability Ladder, the Resource Server
Tiers, and the Authorization Domain Tiers are reporting tools. An
implementation describes its position on the coordinate; it does not
"conform" to a level or tier as if these were independent wire
contracts. IANA actions in this document are limited to formal entry
definitions in the Mission Capability-Advertisement Metadata
Registry created by the Mission Framework and to the closed
enumerations for the three axes.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

The following terms are used as defined in
{{I-D.draft-mcguinness-mission-framework}}:

- Mission, Mission Proposal, Mission Intent, Authority Set,
  Mission-bound credential, state authority, integrity anchors,
  Mission Status.

The following terms are used as defined in
{{I-D.draft-mcguinness-mission-runtime-profile}}:

- Policy Decision Point (PDP), Policy Enforcement Point (PEP),
  Decision Evidence Object, Execution Evidence Object,
  enforcement-scope manifest.

The following terms are used as defined in
{{RFC6749}} and {{RFC9728}}:

- Authorization Server (AS), Resource Server (RS), Protected
  Resource Metadata (PRM).

This document defines no new wire surface. It introduces named
identifiers for capability reporting and the closed enumerations
that hold them.

# Three Adoption Claims

Three named adoption claims serve as the headline signal that a
deployment, vendor, or working group can rally around when
describing itself in a sentence. Each claim has a clear yes-or-no
answer at audit time and maps directly to coordinates on the three
axes defined later.

## Mission-Bound Issuance

The state authority records an Approved Mission with integrity
anchors, issues Mission-bound credentials, and gates credential
derivation (refresh, exchange, substrate-native re-derivation) on
Mission state. Resource Servers MAY remain unchanged. The deployment
gains revocation, audit binding on the Mission identifier, and a
user-visible Mission inventory without changing Resource Server
code.

This claim maps to:

- Capability Ladder Level 1.
- Resource Server Tier A (RS-A) for in-scope Resource Servers.
- Authorization Domain Tier 1 (AD-1) at the state authority.

Mission-Bound Issuance is the smallest deployable Mission-Bound
Authorization claim. It is appropriate for deployments that want the
Mission-layer governance benefits (one user approval driving
revocable, auditable credential derivation) without buying into
Resource Server changes or runtime enforcement on day one.

## Mission-Bound Runtime Enforcement

Within a deployment-named enforcement scope, every consequential
action is evaluated by a Policy Decision Point against the Mission's
versioned policy view, the audience-relevant Authority Set
projection, authenticated actor context, and current Resource
policy, producing a Decision Evidence Object and Execution Evidence
Object per consequential decision.

This claim maps to:

- Capability Ladder Level 4.
- Resource Server Tier D (RS-D) for every consequential Resource
  Server and local-action enforcement point in the named
  enforcement scope.
- Authorization Domain Tier 3 (AD-3) at the state authority.
- The Runtime Enforcement Profile Core
  {{I-D.draft-mcguinness-mission-runtime-profile}}.

The scope is explicit and bounded. A Mission-Bound Runtime
Enforcement claim is valid only for the action classes, Resource
Servers, and execution boundaries listed in the deployment's
enforcement-scope manifest. Action paths the deployment cannot stop
(debug shells, unsanctioned egress routes, direct database
connectors outside an RS-D Resource Server, agent-side tool
invocations not gated by an orchestrator PEP) fall outside the
claim.

## Mission-Bound Cross-Domain Projection

A canonical Mission record is consumed by more than one
authorization domain (one or more OAuth Authorization Servers, one
or more AAuth Person Servers, or both), each consuming domain
validates the projection before issuing local credentials, and
revocation at the canonical record demonstrably terminates
derivation across every consuming domain.

This claim maps to:

- Capability Ladder Level 2 or higher.
- The Mission Authority Server (MAS) topology
  {{I-D.draft-mcguinness-mission-mas}} or an equivalent
  multi-domain validation rule.
- Authorization Domain Tier 2 (AD-2) at each consuming domain, plus
  the projection-validation contract from each substrate's profile.

The three claims are independent in principle. A deployment can
ship Mission-Bound Cross-Domain Projection without Mission-Bound
Runtime Enforcement, or Mission-Bound Runtime Enforcement without
Mission-Bound Cross-Domain Projection. In practice they tend to
climb together, since each new claim adds enforcement points and
authorization domains that the Authority Set must remain coherent
across. The detailed maturity description for any combination is
the coordinate on the three axes.

# The Three Axes

Capability is not a single number. A deployment reports a
coordinate on three related axes. Three axes are useful because
each answers a different question:

- The Capability Ladder describes *how much* of the Mission-Bound
  Authorization spine the deployment implements end to end.
- Resource Server Tiers describe *what each Resource Server does at
  request time*.
- Authorization Domain Tiers describe *what each authorization
  domain offers to its issuers and consumers*.

The coordinate preserves detail that one score would hide. It also
prevents contradictory claims. A deployment cannot, for example,
report Capability Ladder Level 4 if its consequential Resource
Servers are all RS-A, because Level 4 by definition requires RS-D
for the consequential Resource Servers in scope.

## Capability Ladder

Mission-Bound Authorization is designed for incremental adoption. A
deployment can sit at any level on the Capability Ladder and gain
value; higher levels add capability without invalidating lower
ones. The Ladder is a property of the deployment as a whole, scoped
to the deployment-named scope of the claim.

| Level | Short name |
| --- | --- |
| 0 | Substrate-only |
| 1 | Mission-bound issuance |
| 2 | Mission-aware projection |
| 3 | Mission-aware Resource Server |
| 4 | Full Runtime Enforcement |
| 5 | Verifiable governance |

The Ladder is described in detail in {{capability-ladder}}.

## Resource Server Tiers

Resource Server Tiers describe what an individual Resource Server
does with a Mission-bound credential at request time. They are
reported per Resource Server. A deployment-wide Ladder claim is
bounded by the minimum tier among consequential Resource Servers
included in that claim.

| Tier | Short name |
| --- | --- |
| RS-A | Token-only |
| RS-B | Mission-bound credentials |
| RS-C | Authority-aware |
| RS-D | PDP-evaluated |

The tiers are described in detail in {{resource-server-tiers}}.

## Authorization Domain Tiers

Authorization Domain Tiers describe what an authorization domain
(an OAuth Authorization Server, an AAuth Person Server, or a
Mission Authority Server) delivers to its clients, downstream
domains, and Resource Servers. They are reported per authorization
domain.

| Tier | Short name |
| --- | --- |
| AD-1 | Mission-bound issuance |
| AD-2 | Mission-aware projection |
| AD-3 | Authority-aware projection plus authenticated Mission Status |

The tiers are described in detail in {{authorization-domain-tiers}}.

# Capability Ladder

The Capability Ladder describes end-to-end deployment maturity. Each
level corresponds to a coherent governance outcome.

## Level 0: Substrate-only

The deployment runs baseline OAuth 2.0 {{RFC6749}}, OpenID Connect,
or native AAuth without making a Mission-Bound Authorization
governance claim. Native AAuth may carry its own native Mission
construct without making this document's Mission-Bound governance
claim; in that case it remains Level 0 in this capability model.

Level 0 is a correct destination for any deployment that does not
need Mission-layer governance. Single-call user-driven web flows,
machine-to-machine service credentials, short-lived consumer
authorizations where the credential lifetime is the task lifetime,
and any non-agentic deployment without a cross-hop audit
requirement SHOULD remain at Level 0. The Ladder measures progress
*for deployments that have chosen to adopt Mission-Bound
governance*. It does not imply that every OAuth deployment is
behind or that every deployment should climb.

## Level 1: Mission-bound issuance

The state authority stores the governance Mission, commits approved
authority and integrity anchors, issues Mission-bound credentials,
and gates new derivation on Mission state. Mission lifecycle
operations (revoke, suspend, resume, complete) are exposed.
Resource Servers MAY remain at RS-A and need no changes.

Required surfaces:

- OAuth substrate: the OAuth Profile Core
  {{I-D.draft-mcguinness-mission-oauth-profile}}.
- AAuth substrate: the AAuth Composition Profile Core
  {{I-D.draft-mcguinness-mission-aauth-profile}}, which includes
  the governance mapping, Authority Set commitment, hash
  separation, and lifecycle projection over the native AAuth
  Mission.

What a Level 1 deployment buys on day one:

- One user approval drives many resource-specific credentials.
  Revocation at the state authority terminates future derivation
  across every audience.
- Refresh and exchange become governable. A long-running agent
  cannot refresh past a Mission that the user revoked.
- Audit reconstruction across audiences becomes a Mission-binding
  join, not log stitching by timestamp.
- The user has a single place to see and stop in-flight Missions,
  independent of credential expiry.

What Level 1 does not require:

- Reading the `mission` claim at the Resource Server.
- Cross-AS ID-JAG, Mission Expansion wire mechanics, Delegated
  Authority Validation, Concurrent Expansion reconciliation,
  Same-IdP Chain Continuation Assertions, Transaction Token
  Chaining, Capability Source Binding, or any Runtime Enforcement
  Profile surface.
- The MAS topology, cross-substrate Authority Set serialization,
  audience-filtered authority projection (AD-3), or verifiable
  governance evidence (Level 5).
- A Mission Status endpoint, expansion handles, or access-request
  submission. Clients fail-and-restart on inactive Missions at this
  level.

## Level 2: Mission-aware projection

Audience-specific credentials and assertions preserve the Mission
binding and remain bounded by the Mission's approved authority.
When a second authorization domain is involved, that domain
validates the projection before issuing local credentials.

Required surfaces:

- Same-domain audience projection is sufficient where the
  deployment has one authorization domain.
- Multi-AS OAuth additionally uses ID-JAG and the Multi-AS
  validation rules from
  {{I-D.draft-mcguinness-mission-oauth-profile}}.
- AAuth preserves native and governance references through
  resource and auth-token flows per
  {{I-D.draft-mcguinness-mission-aauth-profile}}.
- Cross-substrate deployments add MAS
  {{I-D.draft-mcguinness-mission-mas}}; each substrate is an
  authorized projection issuer.

Level 2 does not require Resource Server changes by itself.
Projection correctness is primarily an issuer and
authorization-domain property at this level. Resource Servers
remain at RS-A unless the deployment also claims Level 3 or
higher.

## Level 3: Mission-aware Resource Server

Resource Servers validate Mission state and enforce
audience-relevant Mission authority against each request.

Required surfaces:

- Level 2.
- RS-C for every consequential Resource Server in scope.
- AD-3 Mission Status at the state authority, or an equivalent
  authenticated issuer-provided view of Mission state and the
  audience-relevant Authority Set projection.

Level 3 is a strong default for production deployments that have
adopted Mission-Bound issuance and now want per-request
enforcement against approved authority, but do not need or want
runtime PDP evaluation.

## Level 4: Full Runtime Enforcement

Every consequential action within the deployment's named
enforcement scope is evaluated against a versioned Mission policy
view through a PEP that can prevent the action, and produces a
runtime evidence record per consequential decision.

Required surfaces:

- Level 3.
- RS-D for every consequential Resource Server and local-action
  enforcement point in scope.
- The Runtime Enforcement Profile Core
  {{I-D.draft-mcguinness-mission-runtime-profile}}.
- An explicit named enforcement scope (the enforcement-scope
  manifest) listing the action classes, Resource Servers, and
  execution boundaries actually mediated by a PEP.

Core surfaces required at Level 4 include reproducible policy
materialization, PEP placement, Capability Source Binding for
catalog-sourced actions, parameter binding, runtime failure
handling, AuthZEN evaluation, authority-expandable denial
handling, the Decision Evidence Object, and the Execution Evidence
Object.

A Level 4 claim is valid only for the consequential action classes
and Resource Servers whose execution paths are actually mediated
by an RS-D or runtime-PEP enforcement boundary. The deployment's
Level 4 claim SHOULD name those action classes and resources.
Action paths the deployment cannot stop fall outside the claim
regardless of how comprehensive the rest of the runtime story is.

## Level 5: Verifiable governance

Selected governance evidence is portable and independently
verifiable across the claim's trust boundaries.

Required surfaces:

- Level 4.
- Interoperable specifications for each claimed optional
  capability. Examples include portable Decision Receipts, Tool
  Binding, and Attestation.

The optional module sketches in
{{I-D.draft-mcguinness-mission-runtime-profile}} are a roadmap
rather than sufficient by themselves for a portable Level 5
claim. When an optional module reaches sufficient implementation
maturity, it is expected to be specified as its own draft and to
be available to underwrite Level 5 claims that cite it. Until
those module specifications exist, Level 5 is best understood as
the named capacity for cross-organizational portability rather
than a coordinate any deployment can claim today.

# Resource Server Tiers

Resource Server Tiers describe what an individual Resource Server
does with a Mission-bound credential at request time. They are
reported per Resource Server.

## RS-A: Token-only

The Resource Server validates the credential (audience, expiry,
scope, signature, sender constraint) and ignores Mission state and
the `mission` claim. RS-A is compatible with the AS-narrowed
credential bounds the issuer applies at issuance time and relies on
the credential issuer to enforce Mission gating at derivation.

RS-A is the credential-only floor. Existing Resource Servers need
no changes to participate in a Level 1 deployment.

## RS-B: Mission-bound credentials

The Resource Server reads the `mission` claim from the credential,
validates that the Mission is active (per local cache, recent
event, or freshness rules), and refuses requests on inactive
Missions. It does not evaluate per-request authority and does not
consult a PDP.

RS-B is appropriate for Resource Servers that want to refuse
requests on a revoked or completed Mission without taking on the
work of evaluating Authority Set entries.

## RS-C: Authority-aware

The Resource Server validates Mission state and enforces Authority
Set entries (per-resource authority, action permits, constraints)
for the audience-relevant projection at request time.

RS-C is the Level 3 minimum for consequential Resource Servers. It
delivers per-request enforcement against approved authority without
the PDP wiring required at Level 4.

## RS-D: PDP-evaluated

The Resource Server consults a PDP for every consequential
request. The PDP evaluates the request against the Mission's
versioned policy view plus current Resource policy and produces a
Decision Evidence Object. The Resource Server (or its PEP) records
an Execution Evidence Object per consequential action.

RS-D is the Level 4 minimum for consequential Resource Servers and
follows the full Runtime Enforcement contract in
{{I-D.draft-mcguinness-mission-runtime-profile}}.

## Ladder requirements at each level

- Level 1: RS-A is sufficient. The Ladder's enforcement at this
  level is at the credential-issuance gate, not at the Resource
  Server.
- Level 2: RS-A is still permitted. Projection correctness is
  primarily an issuer and authorization-domain property.
- Level 3: RS-C minimum for every consequential Resource Server in
  scope.
- Level 4: RS-D for every consequential Resource Server and
  local-action enforcement point in scope.
- Level 5: RS-D plus interoperable specifications for each claimed
  verifiable-governance capability.

A deployment with mixed-tier Resource Servers (some RS-A, some
RS-D) is normal. The reported coordinate SHOULD name its scope, as
discussed in {{mixed-tier-handling}}.

# Authorization Domain Tiers

Authorization Domain Tiers describe what an authorization domain
(an Authorization Server, a Person Server, or a Mission Authority
Server) delivers to its clients, downstream domains, and Resource
Servers. The three tiers map roughly onto the Ladder but are
described from the issuer's perspective rather than the
deployment's. Authorization Servers and Person Servers are
credential issuers, not Resource Servers, so their responsibilities
cannot be described only by an RS tier.

## AD-1: Mission-bound issuance

The authorization domain accepts a Mission Intent (or a
substrate-appropriate proposal), validates and stores a Mission,
issues Mission-bound credentials, gates derivation on Mission
state, and exposes a Mission inventory and lifecycle operations.

AD-1 is required for Ladder Level 1 and above.

## AD-2: Mission-aware projection

The authorization domain delivers AD-1 plus the ability to issue
audience-specific Mission-bound credentials or assertions that
preserve the Mission binding. When projection crosses an
authorization-domain boundary, the receiving domain validates the
binding before issuing local credentials.

AD-2 is required for Ladder Level 2 and above.

## AD-3: Authority-aware projection plus authenticated Mission Status

The authorization domain delivers AD-2 plus an authenticated
Mission Status interface exposing state, integrity hashes, the
audience-filtered Authority Set projection, and `policy_version`
(when Runtime Enforcement is enabled), for Resource Servers and
PDPs. When the state authority also issued the credential, an
authenticated issuer endpoint MAY combine this view with
credential introspection; otherwise the services remain separate.

AD-3 is required for Ladder Level 3 and above.

A deployment reports one Authorization Domain Tier per
authorization domain. In a MAS topology, the MAS reports its
governance tier and each consuming AS or PS separately reports the
projection behavior it implements. There is no separate AD-4 for
Runtime Enforcement. The Runtime Enforcement Profile composes
AD-3 at the state authority with RS-D at the Resource Servers.

# The Coordinate, Not the Score

A deployment's capability description is a coordinate, not a single
number. Each component of the coordinate answers a different
question and is independently auditable. Example coordinates:

- **L1 / RS-A / AD-1.** The state authority issues Mission-bound
  credentials, but Resource Servers ignore the Mission. The
  deployment gets the governance layer (revocation, audit,
  inventory) without per-request enforcement.
- **L3 / RS-C / AD-3.** Resource Servers enforce Authority Set
  entries and Mission state. The state authority exposes
  authenticated Mission Status. No PDP. A strong default for
  production deployments without Runtime Enforcement.
- **L4 / RS-D / AD-3.** PDPs evaluate each consequential request.
  Decision evidence is recorded. Full Runtime Enforcement.
- **L5 / RS-D / AD-3 plus interoperable optional-capability
  specifications.** Portable cryptographic receipts, verifiable
  capability-source bindings, attestation, or another
  independently verifiable capability cited by name. Suitable for
  cross-organizational governance claims.

## Mixed-tier handling

A deployment with mixed-tier Resource Servers is the common case.
An organization can report Level 4 for a bounded agent platform
whose consequential actions all pass through RS-D, while
separately reporting legacy RS-A resources outside that scope. It
cannot report Level 4 for the whole deployment if consequential
in-scope actions bypass RS-D.

When a deployment reports a coordinate with mixed-tier Resource
Servers, it SHOULD:

- Name the scope of the claim, including the action classes,
  Resource Servers, and execution boundaries covered.
- Identify the in-scope Resource Servers and the tier each one
  implements.
- Identify the out-of-scope Resource Servers reachable from the
  same issuer (if any), and state that they are not covered by
  the claim.

Per-Resource-Server capability advertisement at the Resource
Server itself is out of scope for this document. The relevant
mechanisms are PRM {{RFC9728}} and, when available,
{{I-D.draft-mcguinness-oauth-rfc9728bis}} for OAuth-substrate
Resource Servers, and the substrate-specific Resource metadata
for AAuth Resource Servers. The exact field names belong to the
relevant substrate profile rather than to this document.

## Scope statements

A capability coordinate is meaningful only when accompanied by a
scope statement. A scope statement names what the coordinate
covers and what it does not. At minimum, a scope statement
SHOULD identify:

- The substrate or substrates in scope (OAuth, AAuth, MAS).
- The Resource Servers in scope and the tier each implements.
- For a Level 4 claim, the enforcement-scope manifest published by
  the deployment per
  {{I-D.draft-mcguinness-mission-runtime-profile}}.
- The Authorization Domain Tier reported by each authorization
  domain in scope.
- The Mission Framework version and substrate profile versions the
  deployment implements.
- Known capabilities outside the claim, especially action paths
  the deployment cannot mediate (debug shells, unsanctioned egress
  routes, direct database connectors outside an RS-D Resource
  Server, agent-side tool invocations not gated by an orchestrator
  PEP).

A coordinate without a scope statement is not a complete
capability report.

# Cross-Substrate Mapping

The coordinate is substrate-neutral. The same Levels and Tiers
describe deployments built on OAuth alone, on AAuth alone, and on
cross-substrate compositions through a Mission Authority Server.
The protocol obligations are not identical across substrates; each
substrate satisfies its own profile contract. This section names
the substrate-specific mapping for each case.

## OAuth-only

OAuth-only deployments map onto the Ladder through
{{I-D.draft-mcguinness-mission-oauth-profile}}. The default
Mission record home is the OAuth Authorization Server.

- Level 1 corresponds to the OAuth Profile Core.
- Level 2 adds same-domain audience projection or, for multi-AS
  deployments, ID-JAG and the Multi-AS validation rules.
- Level 3 adds RS-C at consequential Resource Servers and AD-3
  Mission Status (authenticated) at the AS, typically through the
  Mission-snapshot introspection projection.
- Level 4 adds Runtime Enforcement Profile Core and RS-D at the
  consequential Resource Servers.
- Level 5 adds interoperable optional-module specifications cited
  by name.

## AAuth-only

AAuth-only deployments map onto the Ladder through
{{I-D.draft-mcguinness-mission-aauth-profile}}. The default
Mission record home is the AAuth Person Server.

- Native AAuth without the AAuth Composition Profile remains
  Level 0 in this capability model even though it carries its own
  native Mission. The Level 0 designation reflects the absence of
  the Mission-Bound governance mapping, Authority Set commitment,
  hash separation, and lifecycle projection that the composition
  profile adds.
- Level 1 corresponds to the AAuth Composition Profile Core, which
  adds the governance mapping over the native Mission.
- Level 2 preserves native and governance references through
  resource and auth-token flows.
- Level 3 adds RS-C behavior at AAuth Resource Servers and the
  authenticated Mission Status projection at the PS.
- Level 4 adds Runtime Enforcement Profile Core composed with the
  AAuth substrate.
- Level 5 adds interoperable optional-module specifications.

## Cross-substrate under MAS

Cross-substrate deployments add the MAS topology
{{I-D.draft-mcguinness-mission-mas}}. The canonical Mission
record lives at the MAS. Each consuming substrate (one or more
OAuth Authorization Servers, one or more AAuth Person Servers, or
both) is an authorized projection issuer.

- The MAS reports its own Authorization Domain Tier (AD-1 or
  higher, depending on the projection and Mission Status surfaces
  it offers).
- Each consuming AS or PS separately reports the Authorization
  Domain Tier it implements for projection validation, local
  credential issuance, and (at AD-3) authenticated Mission Status
  for downstream Resource Servers.
- The deployment's Capability Ladder claim is bounded by the
  minimum coordinate among the consuming substrates that are in
  scope for the claim.
- The Mission-Bound Cross-Domain Projection adoption claim is met
  when the MAS canonical record is consumed by more than one
  consuming domain and revocation at the canonical record
  demonstrably terminates derivation across every consuming
  domain.

In a cross-substrate report, a single deployment-wide Level label
is insufficient. The report SHOULD include the MAS tier, each
consuming domain's tier, and the per-substrate scope statement.

# Capability Advertisement

A state authority MAY advertise its capabilities through metadata.
The Mission Framework {{I-D.draft-mcguinness-mission-framework}}
creates the **Mission Capability-Advertisement Metadata Registry**
and names four metadata fields for that registry. This document
provides the formal registry entries for those fields and the
closed enumerations the field values reference. The IANA actions
appear in {{iana-considerations}}.

The four metadata fields are:

## mission_authorization_domain_tiers_supported

Array of Authorization Domain Tier identifiers (a subset of the
closed enumeration in {{authorization-domain-tier-identifiers}})
that the advertising authorization domain implements.

Example value: `["AD-1", "AD-2", "AD-3"]`.

The advertised tiers represent claimed capability at the
authorization domain. A consumer SHOULD treat the highest tier in
the array as the upper bound of the domain's claim and SHOULD NOT
assume capabilities beyond the listed tiers.

## mission_ladder_levels_supported

Array of integer Capability Ladder level identifiers (a subset of
the closed enumeration in
{{capability-ladder-level-identifiers}}) that the advertising
deployment supports.

Example value: `[1, 2, 3]`.

A deployment SHOULD advertise the highest level it can support
end-to-end within a defined scope, together with each lower level
it remains compatible with. A `mission_ladder_levels_supported`
value is a deployment-level claim, not a per-Resource-Server
claim; per-Resource-Server tier reporting belongs at the Resource
Server's own metadata surface.

## mission_profiles_supported

Array of substrate or runtime profile identifiers the advertising
authorization domain implements. The initial registered string
values are:

- `"oauth"`: the OAuth Profile
  {{I-D.draft-mcguinness-mission-oauth-profile}}.
- `"aauth"`: the AAuth Composition Profile
  {{I-D.draft-mcguinness-mission-aauth-profile}}.
- `"mas"`: the Mission Authority Server Profile
  {{I-D.draft-mcguinness-mission-mas}}.
- `"runtime_enforcement"`: the Runtime Enforcement Profile
  {{I-D.draft-mcguinness-mission-runtime-profile}}.

Additional profile identifiers MAY be added to the
Capability-Advertisement Metadata Registry per the policy in
{{I-D.draft-mcguinness-mission-framework}}.

## mission_optional_modules_supported

Array of registered Mission Runtime Enforcement Profile optional
module identifiers the advertising authorization domain or runtime
implements. The set of registered optional modules is defined by
{{I-D.draft-mcguinness-mission-runtime-profile}} and its
follow-on module specifications. Example values include
`"tool_binding"`, `"decision_receipt"`, `"purpose_registry"`,
`"actor_provenance"`, `"attestation"`, and `"policy_projection"`.

Each value MUST correspond to a registered optional module with a
defining specification. Unregistered tokens are not
interoperable and SHOULD NOT be advertised.

## Metadata location

The metadata location is substrate-specific:

- OAuth uses the AS metadata document.
- AAuth uses the PS metadata document.
- MAS uses its own metadata document defined in
  {{I-D.draft-mcguinness-mission-mas}}.

Resource Server tier and PDP capability are advertised at the
Resource Server through PRM {{RFC9728}} (or
{{I-D.draft-mcguinness-oauth-rfc9728bis}} when available) for
OAuth-substrate Resource Servers, and through the AAuth Resource
metadata for AAuth Resource Servers. The exact field names for
per-Resource-Server tier advertisement are defined by the relevant
substrate profile and are out of scope for this document.

# Reading Paths by Capability Goal

If your deployment goal is...

- **"Bind tokens to a Mission and revoke as one."** Target Ladder
  Level 1 and Authorization Domain Tier 1. Read
  {{I-D.draft-mcguinness-mission-framework}} and the OAuth or
  AAuth profile, plus this document.
- **"Project one Mission across multiple authorization domains."**
  Target Ladder Level 2 or higher and AD-2 at each participating
  issuer domain. Add {{I-D.draft-mcguinness-mission-mas}} if the
  domains need one shared canonical Mission record.
- **"Resource Servers evaluate approved bounds at request time."**
  Target Ladder Level 3 and RS-C. Read the audience-relevant
  Authority Set projection contracts from the OAuth profile, the
  AAuth profile, and (for cross-substrate) the MAS profile.
- **"Every consequential action evaluated through a PDP."** Target
  Ladder Level 4 and RS-D. Read
  {{I-D.draft-mcguinness-mission-runtime-profile}} Core.
- **"Portable third-party-verifiable governance."** Target Ladder
  Level 5. Add an interoperable specification for each claimed
  Runtime Enforcement Profile optional capability, such as
  Decision Receipt, Tool Binding, or Attestation. The optional
  module sketches in
  {{I-D.draft-mcguinness-mission-runtime-profile}} are not
  sufficient alone.

Migration guidance for deployments moving across coordinates lives
in {{I-D.draft-mcguinness-mission-migration}}. Shaper guidance for
deployments framing Mission Intents at the human-task layer lives
in {{I-D.draft-mcguinness-mission-shaper-profile}}.

# Why Informational

This document is Informational. The coordinate, the adoption
claims, and the metadata field semantics are reporting tools.
Conformance is claimed against the testable wire requirements of
a substrate profile or the Runtime Enforcement Profile.

- A deployment claims conformance to
  {{I-D.draft-mcguinness-mission-oauth-profile}} by satisfying its
  OAuth wire contract.
- A deployment claims conformance to
  {{I-D.draft-mcguinness-mission-aauth-profile}} by satisfying its
  AAuth composition contract.
- A deployment claims conformance to
  {{I-D.draft-mcguinness-mission-runtime-profile}} by satisfying
  its PDP, PEP, and evidence contracts within a named
  enforcement scope.
- A deployment claims conformance to
  {{I-D.draft-mcguinness-mission-mas}} by satisfying its
  canonical-record, projection-issuance, and Mission Status
  contracts.

A capability coordinate reports against this document's vocabulary.
A capability coordinate is not itself a conformance claim. An
implementation MUST NOT claim "conformance to" this document; an
implementation describes its position on the coordinate.

IANA actions in this document are confined to formal entries in
the Capability-Advertisement Metadata Registry created by the
Mission Framework and to closed enumerations for the three axes.
This document defines no new wire surface. For these reasons, the
Informational category is the appropriate publication track.

# IANA Considerations  {#iana-considerations}

This document requests IANA registrations in registries created
by {{I-D.draft-mcguinness-mission-framework}} and establishes
three closed enumerations.

## Mission Capability-Advertisement Metadata Registry entries

{{I-D.draft-mcguinness-mission-framework}} creates the
**Mission Capability-Advertisement Metadata Registry** with
Specification Required registration policy. Each entry MUST
include:

- `name`
- value semantics
- defining specification
- change controller

This document registers four entries in that registry. Each entry
references the closed enumerations defined later in this section.

### Entry: mission_authorization_domain_tiers_supported

- **Name**: `mission_authorization_domain_tiers_supported`
- **Value semantics**: JSON array of strings. Each value MUST be
  a registered identifier from
  {{authorization-domain-tier-identifiers}}.
- **Defining specification**: this document, {{capability-advertisement}}.
- **Change controller**: IETF.

### Entry: mission_ladder_levels_supported

- **Name**: `mission_ladder_levels_supported`
- **Value semantics**: JSON array of non-negative integers. Each
  value MUST be a registered identifier from
  {{capability-ladder-level-identifiers}}.
- **Defining specification**: this document, {{capability-advertisement}}.
- **Change controller**: IETF.

### Entry: mission_profiles_supported

- **Name**: `mission_profiles_supported`
- **Value semantics**: JSON array of strings. Each value MUST be
  a registered profile identifier. Initial registered values are
  `"oauth"`, `"aauth"`, `"mas"`, `"runtime_enforcement"`.
  Additional values MAY be registered in the
  Capability-Advertisement Metadata Registry under the policy in
  {{I-D.draft-mcguinness-mission-framework}}.
- **Defining specification**: this document, {{capability-advertisement}}.
- **Change controller**: IETF.

### Entry: mission_optional_modules_supported

- **Name**: `mission_optional_modules_supported`
- **Value semantics**: JSON array of strings. Each value MUST
  correspond to a registered Mission Runtime Enforcement Profile
  optional module with a defining specification. The registry of
  optional module identifiers is maintained by
  {{I-D.draft-mcguinness-mission-runtime-profile}} and its
  follow-on module specifications.
- **Defining specification**: this document, {{capability-advertisement}}.
- **Change controller**: IETF.

## Capability Ladder Level Identifiers  {#capability-ladder-level-identifiers}

This document defines a closed enumeration of Capability Ladder
level identifiers. Conformant deployments reporting a coordinate
under this document MUST use these identifiers.

| Identifier | Short name | Section |
| --- | --- | --- |
| `0` | Substrate-only | {{level-0-substrate-only}} |
| `1` | Mission-bound issuance | {{level-1-mission-bound-issuance}} |
| `2` | Mission-aware projection | {{level-2-mission-aware-projection}} |
| `3` | Mission-aware Resource Server | {{level-3-mission-aware-resource-server}} |
| `4` | Full Runtime Enforcement | {{level-4-full-runtime-enforcement}} |
| `5` | Verifiable governance | {{level-5-verifiable-governance}} |

The enumeration is closed. Extensions or new levels require a
revision of this document or a successor specification. IANA is
not asked to maintain a separate registry for these identifiers.

## Resource Server Tier Identifiers  {#resource-server-tier-identifiers}

This document defines a closed enumeration of Resource Server Tier
identifiers. Conformant deployments reporting a coordinate under
this document MUST use these identifiers.

| Identifier | Short name | Section |
| --- | --- | --- |
| `RS-A` | Token-only | {{rs-a-token-only}} |
| `RS-B` | Mission-bound credentials | {{rs-b-mission-bound-credentials}} |
| `RS-C` | Authority-aware | {{rs-c-authority-aware}} |
| `RS-D` | PDP-evaluated | {{rs-d-pdp-evaluated}} |

The enumeration is closed. Extensions or new tiers require a
revision of this document or a successor specification.

## Authorization Domain Tier Identifiers  {#authorization-domain-tier-identifiers}

This document defines a closed enumeration of Authorization Domain
Tier identifiers. Conformant deployments reporting a coordinate
under this document MUST use these identifiers.

| Identifier | Short name | Section |
| --- | --- | --- |
| `AD-1` | Mission-bound issuance | {{ad-1-mission-bound-issuance}} |
| `AD-2` | Mission-aware projection | {{ad-2-mission-aware-projection}} |
| `AD-3` | Authority-aware projection plus authenticated Mission Status | {{ad-3-authority-aware-projection-plus-authenticated-mission-status}} |

The enumeration is closed. Extensions or new tiers require a
revision of this document or a successor specification.

# Security Considerations

This document defines no new wire surface and no new credentials.
Security properties of Mission-Bound Authorization derive from the
substrate profiles and the Mission Framework. The following
considerations relate to the use of the capability coordinate as
a reporting tool.

**Coordinate is not conformance.** A capability coordinate reports
deployed capability against the vocabulary defined here. It is not
a conformance claim and does not testify to the correctness of any
substrate-profile or runtime-profile implementation. A relying
party SHOULD verify the underlying profile conformance claims
separately rather than relying on the coordinate alone.

**Scope is load-bearing.** A Level 4 claim without a published
enforcement-scope manifest is uninformative and potentially
misleading. A relying party SHOULD treat an unscoped Level 4 or
Level 5 claim with skepticism. Action paths the deployment cannot
mediate (debug shells, unsanctioned egress routes, direct
connectors outside the named scope, agent-side invocations not
gated by an orchestrator PEP) fall outside the claim and may
invalidate its operational value.

**Self-reported capability.** Capability advertisement through
state-authority metadata is self-reported. A relying party
receiving a `mission_ladder_levels_supported` value of `[1, 2, 3,
4]` learns what the issuer claims to support; it does not learn
that any particular request or Mission was handled at that level.
The Mission Framework's integrity-anchor and Mission Status
contracts provide the per-Mission and per-decision evidence
mechanisms; the capability advertisement is orthogonal.

**Misaligned tiers can mislead.** A deployment reporting
`L4 / RS-A / AD-1` is internally inconsistent. Relying parties
SHOULD reject inconsistent coordinates rather than choosing one
component to believe.

# Acknowledgments
{:numbered="false"}

The author thanks the implementers and reviewers of the
Mission-Bound Authorization architecture for feedback that shaped
this specification.
